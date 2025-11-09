#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r'''  Filter Hex-Rays Decompiler Output
xray is a plugin for the Hexrays decompiler that both filters and colorizes the textual representation of the decompiler's output based on configurable regular expressions.
This helps highlighting interesting code patterns which can be useful in malware analysis and vulnerability identification.
'''

import shutil, re, os, configparser, errno
import time as _time
from datetime import datetime as _datetime
from pydantic import validate_call # pip install pydantic
try:
    from PySide6.QtWidgets import QWidget, QSplitter # type: ignore[import-untyped, import-not-found] # >= IDA 9.2
except ImportError:
    from PyQt5 import QWidget, QSplitter # type: ignore[import-untyped, import-not-found] # < IDA 9.2

import ida_hexrays # type: ignore[import-untyped]
import ida_idaapi # type: ignore[import-untyped]
import ida_kernwin # type: ignore[import-untyped]
import ida_lines # type: ignore[import-untyped]
import ida_diskio # type: ignore[import-untyped]
from ida_pro import IDA_SDK_VERSION # type: ignore[import-untyped]

__version__ = "2025-11-08 15:36:01"
__author__ = "Original: Dennis Elser, Updated: Harding"
__description__ = __doc__
__copyright__ = "Copyright 2025"
__credits__ = ["https://github.com/patois/xray"]
__license__ = "GPL 3.0"
__maintainer__ = "Harding"
__email__ = "not.at.the.moment@example.com"
__status__ = "Development"
__url__ = "https://github.com/Harding-Stardust/xray"

_G_PLUGIN_NAME = "xray"
_G_XRAY_FILTER_ACTION_ID = f"{_G_PLUGIN_NAME}:filter"
_G_XRAY_LOADCFG_ACTION_ID = f"{_G_PLUGIN_NAME}:loadcfg"
_G_XRAY_QUERY_ACTION_ID = f"{_G_PLUGIN_NAME}:query"
_G_PATTERN_LIST = []
_G_HIGH_CONTRAST = False

_G_IS_ACTIVATED = False
_G_TEXT_INPUT_FORMS: dict[str, ida_kernwin.Form] = {}

_G_CFG_FILENAME = f"{_G_PLUGIN_NAME}.cfg"
_G_DEFAULT_CFG = """# configuration file for xray.py

[global]
# set to 1 for better contrast
high_contrast=0
# enable/disable xray when loading a database 
auto_enable=0

# each group contains a list of regular
# expressions, a background color in
# RRGGBB format and an optional hint field.
# priority is determined by order of
# appearance, first group gets assigned
# lowest priority.
# check out https://regex101.com/r and
# https://www.debuggex.com/

[group_01]
hint=loop
bgcolor=4c0037

expr_01=^while\\(
expr_02=^for\\(

[group_02]
hint=function name
bgcolor=00374c

expr_01=recv\\(
expr_02=malloc\\(
expr_03=realloc\\(
expr_04=free\\(
expr_05=memcpy\\(
expr_06=memmove\\(
expr_07=strcpy\\(
expr_08=sscanf\\(
expr_09=sprintf\\(
expr_10=recvfrom\\(

[group_03]
hint=format strings
bgcolor=4c1500

expr_01=sscanf\\(.*,.*%s.*,.*\\)
expr_02=sprintf\\(.*,.*%s.*,.*\\)

[group_04]
hint=arithmetic
bgcolor=4c1500

expr_01=malloc\\(.*[\\*\\+\\-\\/%][^>].*?\\)
expr_02=realloc\\(([^,]+,){1}(.*[^,][\\+\\-\\*\\/%][^>].*[^,])
expr_03=memcpy\\(([^,]+,){2}(.*[^,][\\+\\-\\*\\/%][^>].*[^,])
expr_04=memmove\\(([^,]+,){2}(.*[^,][\\+\\-\\*\\/%][^>].*[^,])
expr_05=recv\\(([^,]+,){2}(.*[^,][\\+\\-\\*\\/%][^>].*[^,])
expr_06=recvfrom\\(([^,]+,){2}(.*[^,][\\+\\-\\*\\/%][^>].*[^,])"""

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _simple_logger(arg_logline: str) -> None:
    ''' Prepends the line with a timestamp and appends the filename at the end '''
    l_logline = f"{_time.strftime("%Y-%m-%d %H:%M:%S", _datetime.timetuple(_datetime.now()))}: {arg_logline}                  File: {__file__}"
    print(l_logline)
    return

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def is_plugin() -> bool:
    """returns True if this script is executed from within an IDA plugins
    directory, False otherwise."""
    return "__plugins__" in __name__

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def get_dest_filename() -> str:
    """returns destination path for plugin installation."""
    return os.path.join(ida_diskio.get_user_idadir(), "plugins", f"{_G_PLUGIN_NAME}.py")

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def is_installed() -> bool:
    """checks whether script is present in designated plugins directory."""
    return os.path.isfile(get_dest_filename())

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def get_cfg_filename() -> str:
    """returns full path for config file."""
    # TODO: Allow the user to install the plugin in <idadir>\plugins? --> ida_diskio.get_ida_subdirs("plugins")
    return os.path.join(ida_diskio.get_user_idadir(), "plugins", _G_CFG_FILENAME)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def is_min_sdk_ver(min_ver_required: int):
    return IDA_SDK_VERSION >= min_ver_required

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def is_compatible() -> bool:
    """Checks whether script is compatible with current IDA and
    decompiler versions."""
    min_ida_ver = 720
    return is_min_sdk_ver(min_ida_ver) and ida_hexrays.init_hexrays_plugin()

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def install_plugin() -> bool:
    """Installs script to IDA userdir as a plugin."""
    dst = get_dest_filename()
    src = __file__
    if is_installed():
        btnid = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, f"File exists:\n\n{dst}\n\nReplace?")
        if btnid is not ida_kernwin.ASKBTN_YES:
            return False
    else:
        btnid = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, f"This plugin is about to be installed to:\n\n{dst}\n\nInstall now?")
        if btnid is not ida_kernwin.ASKBTN_YES:
            return False

    usrdir = os.path.dirname(dst)
    _simple_logger(f'copying script from "{src}" to "{usrdir}" ...')
    if not os.path.exists(usrdir):
        try:
            os.makedirs(usrdir)
        except OSError as e:
            if e.errno != errno.EEXIST:
                _simple_logger("failed (mkdir)!")
                return False
    try:
        shutil.copy(src, dst)
    except:
        _simple_logger("failed (copy)!")
        return False
    _simple_logger(("done\nPlugin installed - please restart this instance of IDA"))
    return True

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def swapcol(x: int) -> int:
    """ Converts between RRGGBB and BBGGRR color encodings """
    return (((x & 0x000000FF) << 16) |
             (x & 0x0000FF00) |
            ((x & 0x00FF0000) >> 16))

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def load_cfg(arg_reload: bool = False):
    """ Loads xray configuration from file. Creates and loads default config if none is present """
    global _G_PATTERN_LIST
    global _G_HIGH_CONTRAST
    global _G_IS_ACTIVATED

    cfg_file = get_cfg_filename()
    _simple_logger(f"(re)loading {cfg_file}...")
    if not os.path.isfile(cfg_file):
        _simple_logger(f"{cfg_file} does not exist! creating default config... " )
        try:
            with open(cfg_file, "w", encoding="UTF-8", newline='\n') as f:
                f.write(_G_DEFAULT_CFG)
            _simple_logger("success!")
        except:
            _simple_logger("failed!")
            return False
        return load_cfg(arg_reload=True)

    _G_PATTERN_LIST = []

    config = configparser.RawConfigParser()
    with open(cfg_file) as f:
        config.read_file(f)

    # read all sections
    for section in config.sections():
        expr_list = []
        if section.startswith("group_"):
            for k,v in config.items(section):
                if k.startswith("expr_"):
                    expr_list.append(v)
            try:
                bgcolor = swapcol(int(config.get(section, "bgcolor"), 16))
            except:
                bgcolor = swapcol(0x000000)
            try:
                hint = config.get(section, "hint")
            except:
                hint = None
            _G_PATTERN_LIST.append(ConfigGroupSection(expr_list, bgcolor, hint))
        elif section == "global":
            try:
                _G_HIGH_CONTRAST = config.getboolean(section, "high_contrast")
            except:
                _G_HIGH_CONTRAST = False
            if not arg_reload:
                try:
                    _G_IS_ACTIVATED = config.getboolean(section, "auto_enable")
                except:
                    _G_IS_ACTIVATED = False

    if not len(_G_PATTERN_LIST):
        ida_kernwin.warning("Config file does not contain any regular expressions.")
    return True

class TextInputForm(ida_kernwin.Form):
    """ Input form for regex search queries """

    # flags
    SO_FIND_TEXT = 1
    SO_FIND_REGEX = 2
    SO_FILTER_TEXT = 4
    SO_FILTER_COLOR = 8
    SO_FIND_CASE = 16

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def __init__(self, parent_widget):
        self.parent_widget = parent_widget
        self.parent_title = ida_kernwin.get_widget_title(self.parent_widget)
        i = 1
        while ida_kernwin.find_widget(f"{_G_PLUGIN_NAME}-{i}"):
            i += 1
        self.idx = i
        __title = f"{_G_PLUGIN_NAME}-{self.idx}"
        l_default_settings = TextInputForm.SO_FILTER_COLOR | TextInputForm.SO_FIND_REGEX # original settings: TextInputForm.SO_FILTER_TEXT | TextInputForm.SO_FIND_TEXT
        self.options = (_G_TEXT_INPUT_FORMS[self.parent_title].options if self.parent_title in _G_TEXT_INPUT_FORMS.keys() else l_default_settings)
        self.query = (_G_TEXT_INPUT_FORMS[self.parent_title].query if self.parent_title in _G_TEXT_INPUT_FORMS.keys() else "")
        ida_kernwin.Form.__init__(self,
("BUTTON YES NONE\n"
"BUTTON NO NONE\n"
"BUTTON CANCEL NONE\n"
"%s\n\n"
"{FormChangeCb}\n"
"<##Enter text##Filter:{cbEditable}>"
"|<##Search##Text:{rText}><Regex:{rRegex}>{cSearchMethod}>"
"|<##Filter##Lines:{rFilterLines}><Colors:{rFilterColors}>{cFilterType}>"
"|<##Options##Case sensitive:{rCase}>{cOptions}>\n") % (__title), {
    'FormChangeCb': ida_kernwin.Form.FormChangeCb(self.OnFormChange),
    'cbEditable': ida_kernwin.Form.StringInput(value = self.query),
    'cSearchMethod': ida_kernwin.Form.RadGroupControl(("rText", "rRegex")),
    'cFilterType': ida_kernwin.Form.RadGroupControl(("rFilterLines", "rFilterColors")),
    'cOptions': ida_kernwin.Form.ChkGroupControl(("rCase",))})

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def init_controls(self) -> None:
        ''' Set the correct settings when showing the Form '''
        self.SetControlValue(self.cbEditable, self.query)
        self.SetControlValue(self.cSearchMethod, 0 if self.options & TextInputForm.SO_FIND_TEXT else 1)
        self.SetControlValue(self.cFilterType, 0 if self.options & TextInputForm.SO_FILTER_TEXT else 1)
        self.SetControlValue(self.cOptions, 1 if self.options & TextInputForm.SO_FIND_CASE else 0)
        self.SetFocusedField(self.cbEditable)
        return

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _commit_changes(self) -> bool:
        vu = ida_hexrays.get_widget_vdui(self.parent_widget)
        if vu:
            vu.refresh_ctext()
            # "refresh_ctext()" took away the focus, take it back
            ida_kernwin.activate_widget(ida_kernwin.find_widget(self.title), True)
            self.SetFocusedField(self.cbEditable)
            return True
        return False

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def OnFormChange(self, fid) -> int:
        if fid == self.cbEditable.id:
            self.query = self.GetControlValue(self.cbEditable)
        elif fid == self.rCase.id:
            if self.GetControlValue(self.cOptions):
                self.options |= TextInputForm.SO_FIND_CASE
            else:
                self.options &= ~TextInputForm.SO_FIND_CASE & 0xFFFFFFFF
        elif fid in [self.rFilterLines.id, self.rFilterColors.id]:
            filter_text = fid == self.rFilterLines.id
            filter_color = fid == self.rFilterColors.id

            if filter_text:
                self.options |= TextInputForm.SO_FILTER_TEXT
            else:
                self.options &= ~TextInputForm.SO_FILTER_TEXT & 0xFFFFFFFF

            if filter_color:
                self.options |= TextInputForm.SO_FILTER_COLOR
            else:
                self.options &= ~TextInputForm.SO_FILTER_COLOR & 0xFFFFFFFF
        elif fid in [self.rText.id, self.rRegex.id]:
            find_text = fid == self.rText.id
            find_regex = fid == self.rRegex.id

            if find_text:
                self.options |= TextInputForm.SO_FIND_TEXT
            else:
                self.options &= ~TextInputForm.SO_FIND_TEXT & 0xFFFFFFFF

            if find_regex:
                self.options |= TextInputForm.SO_FIND_REGEX
            else:
                self.options &= ~TextInputForm.SO_FIND_REGEX & 0xFFFFFFFF
        
        self._commit_changes()
        return 1

class ConfigGroupSection():
    """class that represents a config file's "group" section."""
    def __init__(self, expr_list, bgcolor, hint):
        self.expr_list = expr_list
        self.bgcolor = bgcolor
        self.hint = hint

class xray_hooks_t(ida_hexrays.Hexrays_Hooks):
    """class for handling decompiler events."""

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})    
    def _remove_color_tags(self, l):
        """ Removes all color tags from a tagged simple_line_t object
        but preserves COLOR_ADDR tags. """
        line = ""
        i = 0
        while i < len(l):
            if l[i] is ida_lines.COLOR_ON:
                n = ida_lines.tag_skipcode(l[i:])
                if l[i:].find(chr(ida_lines.COLOR_ADDR)) == 1:
                    line += l[i:i+n]
                i += n
            elif l[i] in [ida_lines.COLOR_OFF, ida_lines.COLOR_ESC, ida_lines.COLOR_INV]:
                n = ida_lines.tag_skipcode(l[i:])
                i += n
            else:
                line += l[i]
                i += 1
        return line
    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _search(self, arg_regexp: str, arg_simple_line: ida_kernwin.simpleline_t, case_sensitive: bool = False) -> bool:
        line = ida_lines.tag_remove(arg_simple_line.line).strip()
        return re.search(arg_regexp, line, flags=re.I if not case_sensitive else 0) is not None

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _apply_xray_filter(self, arg_vu: ida_hexrays.vdui_t, arg_pseudocode_vector_of_simple_line):
        del arg_vu # never used
        if _G_IS_ACTIVATED and arg_pseudocode_vector_of_simple_line:
            #col = ida_lines.calc_bg_color(ida_idaapi.get_inf_structure().min_ea)
            #col = pc[0].bgcolor
            for l_simple_line in arg_pseudocode_vector_of_simple_line:
                match = False
                for group in _G_PATTERN_LIST:
                    for expr in group.expr_list:
                        if self._search(expr, l_simple_line):
                            #sl.bgcolor = (col & 0xfefefe) >> 1
                            l_simple_line.bgcolor = group.bgcolor
                            match=True
                            break
                if not match and _G_HIGH_CONTRAST:
                    l_simple_line.line = self._remove_color_tags(l_simple_line.line)
        return

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _apply_query_filter(self, arg_vu: ida_hexrays.vdui_t, arg_pseudocode_as_vector_of_simple_line):
        l_simple_line: ida_kernwin.simpleline_t
        l_new_pseudocode = []
        title = ida_kernwin.get_widget_title(arg_vu.ct)
        if title in _G_TEXT_INPUT_FORMS.keys() and arg_pseudocode_as_vector_of_simple_line:
            sq = _G_TEXT_INPUT_FORMS[title]
            query = sq.query
            if not len(query):
                ida_kernwin.set_highlight(arg_vu.ct, None, HL_FLAGS)
                return
            options = sq.options
            case_sensitive: bool = bool(options & TextInputForm.SO_FIND_CASE)

            # TODO: no idea what this TODO is here for
            if options & TextInputForm.SO_FIND_TEXT:
                ida_kernwin.set_highlight(arg_vu.ct, query, HL_FLAGS)
                tmpquery = query.lower() if not case_sensitive else query
                for l_simple_line in arg_pseudocode_as_vector_of_simple_line:
                    haystack = ida_lines.tag_remove(l_simple_line.line).strip()
                    haystack = haystack.lower() if not case_sensitive else haystack
                    if tmpquery in haystack:
                        l_new_pseudocode.append(l_simple_line.line)
                    else:
                        if options & TextInputForm.SO_FILTER_COLOR:
                            # add line but remove color
                            l_new_pseudocode.append(self._remove_color_tags(l_simple_line.line))
                        elif options & TextInputForm.SO_FILTER_TEXT:
                            # do not add non-matching text
                            pass
            elif options & TextInputForm.SO_FIND_REGEX:
                ida_kernwin.set_highlight(arg_vu.ct, None, 0)
                for l_simple_line in arg_pseudocode_as_vector_of_simple_line:
                    try:
                        if self._search(query, l_simple_line, case_sensitive):
                            l_new_pseudocode.append(l_simple_line.line)
                        else:
                            if options & TextInputForm.SO_FILTER_COLOR:
                                l_new_pseudocode.append(self._remove_color_tags(l_simple_line.line))
                            elif options & TextInputForm.SO_FILTER_TEXT:
                                # do not add non-matching text
                                pass
                    except re.error as error:
                        _simple_logger(f'{error}: "{query}"')
                        return
            arg_pseudocode_as_vector_of_simple_line.clear()
            l_simple_line = ida_kernwin.simpleline_t()
            for line in l_new_pseudocode:
                l_simple_line.line = line
                arg_pseudocode_as_vector_of_simple_line.push_back(l_simple_line)
        return

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _build_hint(self, arg_vu: ida_hexrays.vdui_t):
        if _G_IS_ACTIVATED and arg_vu.refresh_cpos(ida_hexrays.USE_MOUSE):
            l_simple_line: ida_kernwin.simpleline_t = arg_vu.cfunc.get_pseudocode()[arg_vu.cpos.lnnum]
            hint_lines = ["%s pattern(s):" % _G_PLUGIN_NAME]
            delim_s = "%s" % "="*len(hint_lines[0])
            delim_e = "\n%s\n" % ("-"*len(hint_lines[0]))
            hint_lines.append(delim_s)
            hint = ""
            hint_created = False
            for group in _G_PATTERN_LIST:
                for expr in group.expr_list:
                    if self._search(expr, l_simple_line):
                        tmp = (" (%s)" % group.hint) if group.hint else ""
                        hint_lines.append("> \"%s\"%s" % (expr, tmp))
                        hint_created = True
            hint_lines.append(delim_e)
            hint = "\n".join(hint_lines)
            if hint_created:
                return (hint, len(hint_lines)+1)
        return None
    
    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def text_ready(self, vu: ida_hexrays.vdui_t):
        l_pseudo_code_as_vector_of_simple_line = vu.cfunc.get_pseudocode()
        self._apply_query_filter(vu, l_pseudo_code_as_vector_of_simple_line)
        self._apply_xray_filter(vu, l_pseudo_code_as_vector_of_simple_line)
        return 0
    
    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def populating_popup(self, widget, phandle, vu):
        ida_kernwin.attach_action_to_popup(vu.ct, None, _G_XRAY_FILTER_ACTION_ID, _G_PLUGIN_NAME+"/")
        ida_kernwin.attach_action_to_popup(vu.ct, None, _G_XRAY_LOADCFG_ACTION_ID, _G_PLUGIN_NAME+"/")
        ida_kernwin.attach_action_to_popup(vu.ct, None, _G_XRAY_QUERY_ACTION_ID, _G_PLUGIN_NAME+"/")
        return 0

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def create_hint(self, vu):
        result = self._build_hint(vu)
        if result:
            hint, count = result
            return (2, hint, count)
        return (0, None)

# -----------------------------------------------------------------------------
class xray_action_handler_t(ida_kernwin.action_handler_t):
    """action handler for turning xray on and off."""
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def activate(self, ctx) -> int:
        global _G_IS_ACTIVATED
        _G_IS_ACTIVATED = not _G_IS_ACTIVATED
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        if vu:
            vu.refresh_ctext()
        _simple_logger(f"{"" if _G_IS_ACTIVATED else "de"}activated")
        return 1

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else \
            ida_kernwin.AST_DISABLE_FOR_WIDGET

# -----------------------------------------------------------------------------
class loadcfg_action_handler_t(ida_kernwin.action_handler_t):
    """action handler for reloading xray cfg file."""
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def activate(self, ctx):
        if load_cfg(arg_reload=True):
            vu = ida_hexrays.get_widget_vdui(ctx.widget)
            if vu:
                vu.refresh_ctext()
        return 1

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else \
            ida_kernwin.AST_DISABLE_FOR_WIDGET

# -----------------------------------------------------------------------------
class regexfilter_action_handler_t(ida_kernwin.action_handler_t):
    """action handler for search queries."""
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    
    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _dirty_resize_hack(self, w, form: ida_kernwin.Form):
        ''' The original file had a TODO here '''
        title = form.title
        widget = ida_kernwin.find_widget(title)
        if not widget:
            return

        w1 = ida_kernwin.PluginForm.TWidgetToPyQtWidget(widget)
        w2 = ida_kernwin.PluginForm.TWidgetToPyQtWidget(w)
        if not w1 or not w2:
            return

        p1 = w1.parentWidget()
        p2 = w2.parentWidget()
        if not p1 or not p2:
            return

        splitter = p1.parentWidget()
        hr = p2.parentWidget()
        if not splitter or not hr:
            return

        if not type(splitter) is QSplitter or not type(hr) is QWidget:
            return

        sizes = splitter.sizes()
        if len(sizes) != 2:
            return

        idx = splitter.indexOf(p1)
        _min, _max = splitter.getRange(idx)
        sizes[idx] = _min

        idx = splitter.indexOf(hr)
        _min, _max = splitter.getRange(idx)
        sizes[idx] = _max

        splitter.setSizes(sizes)
        return

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _open_search_form(self, widget):
        global _G_TEXT_INPUT_FORMS

        title = ida_kernwin.get_widget_title(widget)
        if title not in _G_TEXT_INPUT_FORMS.keys():
            # New form
            search_form = TextInputForm(widget)
            search_form.modal = False
            search_form.openform_flags = (ida_kernwin.PluginForm.WOPN_DP_BOTTOM | ida_kernwin.PluginForm.WOPN_PERSIST)
            search_form, _ = search_form.Compile()
            search_form.Open()
            _G_TEXT_INPUT_FORMS[title] = search_form
            self._dirty_resize_hack(widget, search_form)
        else:
            # Form exists from before
            search_form = _G_TEXT_INPUT_FORMS[title]
            search_form.Open()
            self._dirty_resize_hack(widget, search_form)
        search_form.init_controls()
        return

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        self._open_search_form(ctx.widget)
        return 1

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else \
            ida_kernwin.AST_DISABLE_FOR_WIDGET

# -----------------------------------------------------------------------------
class xray_plugin_t(ida_idaapi.plugin_t):
    """ plugin class """
    flags = ida_idaapi.PLUGIN_HIDE
    comment = "Filters and colorizes the textual representation of the decompiler's output based on configurable regular expressions"
    help = "Filters and colorizes the textual representation of the decompiler's output based on configurable regular expressions"
    wanted_name = _G_PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        self.xray_hooks = None
        if not is_compatible():
            _simple_logger(f"decompiler not available, skipping.")
            return ida_idaapi.PLUGIN_SKIP

        load_cfg()

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                _G_XRAY_LOADCFG_ACTION_ID,
                "%s: reload config" % _G_PLUGIN_NAME,
                loadcfg_action_handler_t(),
                "Ctrl-R"))

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                _G_XRAY_FILTER_ACTION_ID,
                "%s: toggle" % _G_PLUGIN_NAME,
                xray_action_handler_t(),
                "F3"))

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                _G_XRAY_QUERY_ACTION_ID,
                "%s: search" % _G_PLUGIN_NAME,
                regexfilter_action_handler_t(),
                "Ctrl-F"))

        self.xray_hooks = xray_hooks_t()
        self.xray_hooks.hook()
        _simple_logger("F3: toggle xray, Ctrl-F: filter, Ctrl-R: reload config")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        return

    def term(self):
        if self.xray_hooks:
            self.xray_hooks.unhook()
            ida_kernwin.unregister_action(_G_XRAY_FILTER_ACTION_ID)
            ida_kernwin.unregister_action(_G_XRAY_LOADCFG_ACTION_ID)
            ida_kernwin.unregister_action(_G_XRAY_QUERY_ACTION_ID)
        return

# -----------------------------------------------------------------------------
def PLUGIN_ENTRY():
    """plugin entry point."""
    return xray_plugin_t()

# -----------------------------------------------------------------------------
def SCRIPT_ENTRY():
    """script entry point."""
    if not is_plugin():
        (ida_kernwin.info("Success!") if install_plugin() else
            ida_kernwin.warning("Error! Plugin could not be installed!"))
    return

# -----------------------------------------------------------------------------

HL_FLAGS = ida_kernwin.HIF_LOCKED
if is_min_sdk_ver(740):
    HL_FLAGS |= ida_kernwin.HIF_NOCASE
if is_min_sdk_ver(770):
    HL_FLAGS |= ida_kernwin.HIF_USE_SLOT

SCRIPT_ENTRY()
