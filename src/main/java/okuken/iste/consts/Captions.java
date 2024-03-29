package okuken.iste.consts;

public class Captions {

	public static final String EXTENSION_NAME = "Integrated Security Testing Environment";
	public static final String EXTENSION_NAME_FULL = "ISTE: Integrated Security Testing Environment";

	public static final String OMIT_STRING = "...";
	public static final String CHECK = "\u2713";
	public static final String CHAIN = new String(new int[] {0x1f517}, 0, 1);
	public static final String SEARCH = new String(new int[] {0x1f50d}, 0, 1);

	public static final String DOCKOUT = "\u2197";
	public static final String DOCKOUT_TT = "Undock";
	public static final String DOCKIN = "\u2199";
	public static final String DOCKIN_TT = "Dock";

	public static final String FILECHOOSER = "...";

	public static final String ADD = "\u2795"; //+
	public static final String DELETE = "\u2716"; //x
	public static final String UP = "↑";
	public static final String DOWN = "↓";
	public static final String TABLE_CONTROL_BUTTON_ADD = "+";
	public static final String TABLE_CONTROL_BUTTON_ADD_TT = "Add row {Shift: insert}";
	public static final String TABLE_CONTROL_BUTTON_DELETE = "-";
	public static final String TABLE_CONTROL_BUTTON_DELETE_TT = "Delete selected rows";
	public static final String TABLE_CONTROL_BUTTON_UP = "↑";
	public static final String TABLE_CONTROL_BUTTON_UP_TT = "Up selected rows";
	public static final String TABLE_CONTROL_BUTTON_DOWN = "↓";
	public static final String TABLE_CONTROL_BUTTON_DOWN_TT = "Down selected rows";

	public static final String SAVE = "Save";
	public static final String COPY = "Copy";

	public static final String OK = "OK";
	public static final String CANCEL = "Cancel";

	public static final String CONTEXT_MENU_SEND_TO = "Send to ISTE";
	public static final String CONTEXT_MENU_SEND_TO_HISTORY = "Send to ISTE as history of repeat";

	public static final String TAB_SUITE = "ISTE";
	public static final String TAB_MAIN = "List";
	public static final String TAB_MEMO = "Notes";
	public static final String TAB_AUTH = "Auth";
	public static final String TAB_TOOLS = "Tools";
	public static final String TAB_OPTIONS = "Options";
	public static final String TAB_PLUGINS = "Plugins";
	public static final String TAB_ABOUT = "About";

	public static final String TAB_MAIN_MESSAGE_EDITOR_ORIGINAL = "Org";
	public static final String TAB_MAIN_MESSAGE_EDITOR_REPEAT_MASTER = "Master";
	public static final String TAB_MAIN_MESSAGE_EDITOR_REPEAT = "Repeater";
	public static final String TAB_MAIN_MESSAGE_EDITOR_CHAIN = "Chain";

	public static final String TAB_TOOLS_EXPORT = "Export / Import";
	public static final String TAB_TOOLS_BSQLI = "BSQLi";

	public static final String TAB_OPTIONS_PROJECT_OPTIONS = "Project options";
	public static final String TAB_OPTIONS_USER_OPTIONS = "User options";
	public static final String TAB_OPTIONS_USER_OPTIONS_MISC = "Misc";
	public static final String TAB_OPTIONS_USER_OPTIONS_TEMPLATE = "Note templates";
	public static final String TAB_OPTIONS_USER_OPTIONS_COPY_TEMPLATE = "Copy templates";

	public static final String TAB_MESSAGE_EDITOR_REQUEST = "Request";
	public static final String TAB_MESSAGE_EDITOR_RESPONSE = "Response";

	public static final String MAIN_HEADER_CHECKBOX_FILTER_PROGRESS_TT = "Filter rows by progress";
	public static final String MAIN_HEADER_INPUT_FILTER_TERM_TT = "Filter rows by search term";
	public static final String MAIN_HEADER_BUTTON_CHANGE_PROJECT = "...";
	public static final String MAIN_HEADER_BUTTON_CHANGE_PROJECT_TT = "Select ISTE project";
	public static final String MAIN_HEADER_ALERT_PROJECT_TT = "Selected ISTE project's name is different from Burp's one.";
	public static final String MAIN_HEADER_BUTTON_INIT_COLUMN_WIDTH = "\u2194";
	public static final String MAIN_HEADER_BUTTON_INIT_COLUMN_WIDTH_TT = "Adjust layout";

	public static final String TABLE_CONTEXT_MENU_SEND_REQUEST_REPEATER = "Issue request (Repeater)";
	public static final String TABLE_CONTEXT_MENU_EXPLOIT_TOOL = "Exploit";
	public static final String TABLE_CONTEXT_MENU_EXPLOIT_TOOL_BSQLI = "Blind SQL injection";
	public static final String TABLE_CONTEXT_MENU_DO_PASSIVE_SCAN = "Do passive scan";
	public static final String TABLE_CONTEXT_MENU_DO_ACTIVE_SCAN = "Do active scan";
	public static final String TABLE_CONTEXT_MENU_SEND_TO_INTRUDER = "Send to Intruder";
	public static final String TABLE_CONTEXT_MENU_SEND_TO_REPEATER = "Send to Repeater";
	public static final String TABLE_CONTEXT_MENU_SEND_TO_COMPARER_REQUEST = "Send to Comparer (request)";
	public static final String TABLE_CONTEXT_MENU_SEND_TO_COMPARER_REQUEST_WITH_ORG = "Send to Comparer (request) with Org";
	public static final String TABLE_CONTEXT_MENU_SEND_TO_COMPARER_REQUEST_WITH_MST = "Send to Comparer (request) with Master";
	public static final String TABLE_CONTEXT_MENU_SEND_TO_COMPARER_RESPONSE = "Send to Comparer (response)";
	public static final String TABLE_CONTEXT_MENU_SEND_TO_COMPARER_RESPONSE_WITH_ORG = "Send to Comparer (response) with Org";
	public static final String TABLE_CONTEXT_MENU_SEND_TO_COMPARER_RESPONSE_WITH_MST = "Send to Comparer (response) with Master";
	public static final String TABLE_CONTEXT_MENU_OPEN_CHAIN = "Open chain";
	public static final String TABLE_CONTEXT_MENU_CREATE_CHAIN = "Create chain";
	public static final String TABLE_CONTEXT_MENU_CREATE_AUTH_CHAIN = "Create auth chain";
	public static final String TABLE_CONTEXT_MENU_EDIT_CELL = "Edit cell";
	public static final String TABLE_CONTEXT_MENU_DELETE_ITEM = "Delete item";
	public static final String TABLE_CONTEXT_MENU_COPY_NAME = "Copy name";
	public static final String TABLE_CONTEXT_MENU_COPY_NAME_WITHOUTNUMBER = "Copy name without number";
	public static final String TABLE_CONTEXT_MENU_COPY_URL = "Copy URL";
	public static final String TABLE_CONTEXT_MENU_COPY_URL_WITHOUTQUERY = "Copy URL without Query";
	public static final String TABLE_CONTEXT_MENU_COPY_TABLE = "Copy as table";
	public static final String TABLE_CONTEXT_MENU_COPY_BY_TEMPLATE_PREFIX = "Copy ";
	public static final String TABLE_CONTEXT_MENU_PASTE_TABLE = "Paste as table (insert)";

	public static final String TABLE_CELL_EDITOR_INPUT = "Input";
	public static final String TABLE_CELL_EDITOR_REPLACE = "Replace(Regex)";
	public static final String TABLE_CELL_EDITOR_NUMBERING = "Numbering";
	public static final String TABLE_CELL_EDITOR_NUMBERING_FROM = "from";

	public static final String REPEAT_HISTORY_CAPTION_BY_SEND_TO = "[Send to ISTE]";

	public static final String REPEATER_BUTTON_SEND = "Send";
	public static final String REPEATER_BUTTON_SEND_TT = "Issue request in message editor as selected account {Shift: with refresh session}";
	public static final String REPEATER_COMBOBOX_ACCOUNT_TT = "Select account";
	public static final String REPEATER_BUTTON_AUTH_SESSION_REFRESH = "\uD83D\uDD04";
	public static final String REPEATER_BUTTON_AUTH_SESSION_REFRESH_TT = "Refresh session of selected account [Alt+R]";
	public static final String REPEATER_BUTTON_COPY_ORG = "Org";
	public static final String REPEATER_BUTTON_COPY_ORG_TT = "Set original message to message editor";
	public static final String REPEATER_BUTTON_COPY_MASTER = "Master";
	public static final String REPEATER_BUTTON_COPY_MASTER_TT = "Set master message to message editor";
	public static final String REPEATER_BUTTON_FOLLOW_REDIRECT = "Follow redirection";
	public static final String REPEATER_BUTTON_SAVE_AS_MASTER = "Save as master";
	public static final String REPEATER_BUTTON_SAVE_AS_MASTER_TT = "Save message in message editor as master";
	public static final String REPEATER_BUTTON_CHAIN = "Chain";
	public static final String REPEATER_BUTTON_CHAIN_TT = "Open request chain window";

	public static final String REPEATER_POPUP_TITLE_SUFFIX_CHAIN = " - Chain";

	public static final String CHAIN_REPEATER_BUTTON_EDIT_CHAIN = "Edit request chain";
	public static final String CHAIN_REPEATER_POPUP_TITLE_SUFFIX_EDIT_CHAIN = " - Edit request chain";

	public static final String CHAIN_DEF_NODE_BUTTON_ADD = "\u2795"; //+
	public static final String CHAIN_DEF_NODE_BUTTON_ADD_TT = "Add request here";
	public static final String CHAIN_DEF_NODE_BUTTON_DELETE = "\u2716"; //x
	public static final String CHAIN_DEF_NODE_BUTTON_DELETE_TT = "Remove this request from chain";
	public static final String CHAIN_DEF_NODE_BUTTON_UP = "\u2b06";
	public static final String CHAIN_DEF_NODE_BUTTON_UP_TT = "Move up this request";
	public static final String CHAIN_DEF_NODE_BUTTON_DOWN = "\u2b07";
	public static final String CHAIN_DEF_NODE_BUTTON_DOWN_TT = "Move down this request";

	public static final String CHAIN_DEF_NODE_MESSAGE_CHECKBOX_BREAK_POINT = "Break";
	public static final String CHAIN_DEF_NODE_MESSAGE_CHECKBOX_BREAK_POINT_TT = "Breakpoint";
	public static final String CHAIN_DEF_NODE_MESSAGE_CHECKBOX_SKIP = "Skip";
	public static final String CHAIN_DEF_NODE_MESSAGE_CHECKBOX_SKIP_TT = "Skip this request";
	public static final String CHAIN_DEF_NODE_MESSAGE_BUTTON_SEND = "Send";
	public static final String CHAIN_DEF_NODE_MESSAGE_BUTTON_SEND_TT = "Issue SINGLE request as selected account {Shift: with refresh session}";

	public static final String CHAIN_DEF_TABLE_TITLE_PRESET_VARS = "Preset vars";
	public static final String CHAIN_DEF_TABLE_TITLE_REQUEST_MANIPULATION = "Request manipulation";
	public static final String CHAIN_DEF_TABLE_TITLE_RESPONSE_MEMORIZATION = "Response memorization";

	public static final String CHAIN_DEF_RUN = " \u25b6 ";
	public static final String CHAIN_DEF_RUN_TT = "Start or resume request chain {Shift: with refresh session} [Alt+S]";
	public static final String CHAIN_DEF_TERMINATE = " \u23f9 ";
	public static final String CHAIN_DEF_TERMINATE_TT = "Terminate request chain [Alt+T]";
	public static final String CHAIN_DEF_STEP = " \u2b07 ";
	public static final String CHAIN_DEF_STEP_TT = "Step request chain {Shift: with refresh session} [Alt+F]";
	public static final String CHAIN_DEF_RUN_DONE = "Done.";
	public static final String CHAIN_DEF_RUN_TERMINATE_FORCE = "Forced termination.";

	public static final String CHAIN_DEF_SAVE = "Save";
	public static final String CHAIN_DEF_CANCEL = "Cancel";

	public static final String CHAIN_DEF_SEMIAUTO_SETTING = "Semi-auto setting";
	public static final String CHAIN_DEF_SEMIAUTO_SETTING_COOKIE = "Cookie";
	public static final String CHAIN_DEF_SEMIAUTO_SETTING_COOKIE_TT = "Add cookie transfer settings semi-automatically";

	public static final String CHAIN_DEF_SEMIAUTO_SETTING_TOKEN = "Token";
	public static final String CHAIN_DEF_SEMIAUTO_SETTING_TOKEN_TT = "Add token transfer settings semi-automatically";
	public static final String CHAIN_DEF_SEMIAUTO_SETTING_TOKEN_ATTR_NAME_KEY = "key attr";
	public static final String CHAIN_DEF_SEMIAUTO_SETTING_TOKEN_ATTR_NAME_VALUE = "value attr";
	public static final String CHAIN_DEF_SEMIAUTO_SETTING_TOKEN_REQUEST_PARAM_NAME = "Request parameter";

	public static final String CHAIN_DEF_SPLIT_COLLAPSE = "<";
	public static final String CHAIN_DEF_SPLIT_COLLAPSE_TT = "Collapse manipulation setting panels";
	public static final String CHAIN_DEF_SPLIT_EXPAND = ">";
	public static final String CHAIN_DEF_SPLIT_EXPAND_TT = "Expand manipulation setting panels";
	public static final String CHAIN_DEF_AUTO_SCROLL = "Auto scroll";
	public static final String CHAIN_DEF_AUTO_SCROLL_TT = "Auto scroll to breaking request";

	public static final String MESSAGE_EDITORS_LAYOUT_TYPE_COMBOBOX_TT = "Select layout of message editors";

	public static final String MESSAGE_MEMO_TOGGLE_PIN = "\uD83D\uDCCC";
	public static final String MESSAGE_MEMO_TOGGLE_PIN_TT = "Pin the notes";

	public static final String PROJECT_MEMO_BUTTON_WRAP = "\u21A9";
	public static final String PROJECT_MEMO_BUTTON_WRAP_TT = "Wrap text";

	public static final String AUTH_CONFIG_TABLE_TITLE_ACCOUNTS = "Accounts";
	public static final String AUTH_CONFIG_TABLE_TITLE_APPLY_CONFIG = "How to apply vars provided by authentication request chain to each repeat requests";

	public static final String AUTH_CONFIG_CHAIN = "Authentication request chain";
	public static final String AUTH_CONFIG_BUTTON_EDIT_CHAIN = "Edit authentication request chain";
	public static final String AUTH_CONFIG_BUTTON_EDIT_CHAIN_TT = "Open authentication request chain window";
	public static final String AUTH_CONFIG_POPUP_TITLE_EDIT_CHAIN = "Auth config - Edit request chain";

	public static final String TOOLS_EXPLOIT_ATTACK = "Start attack";
	public static final String TOOLS_EXPLOIT_STOP = "Stop";
	public static final String TOOLS_EXPLOIT_SET = "Set";
	public static final String TOOLS_EXPLOIT_USE_CHAIN = "Use chain (*not implemented now)";
	public static final String TOOLS_EXPLOIT_NEED_URLENCODE = "Need URL-encode";
	public static final String TOOLS_EXPLOIT_INTERVAL_TIME = "Interval time (ms)";
	public static final String TOOLS_EXPLOIT_START_INDEX = "Start index";
	public static final String TOOLS_EXPLOIT_MAX_INDEX = "Max index (for safety)";

	public static final String TOOLS_EXPLOIT_BSQLI_TITLE = "[Experimental feature] Blind SQL injection tool. It performs binary search using ASCII characters(0x00-0x7F).";
	public static final String TOOLS_EXPLOIT_BSQLI_JUDGEBY = "Determine if the test value is correct by";
	public static final String TOOLS_EXPLOIT_BSQLI_JUDGEBY_LENGTH = "Length";
	public static final String TOOLS_EXPLOIT_BSQLI_JUDGEBY_TIME = "Time(ms)";
	public static final String TOOLS_EXPLOIT_BSQLI_JUDGEBY_REGEX = "Regex";
	public static final String TOOLS_EXPLOIT_BSQLI_JUDGEBY_REGEX_INVERSE = "Inverse";
	public static final String TOOLS_EXPLOIT_BSQLI_BUTTON_INDEX_TT  = "Insert an INDEX position marker.\n"
	                                                                + "e.g. 'and((SELECT(ASCII(SUBSTRING(version(),3,1))))<64)and''='\n"
	                                                                + "  -> 'and((SELECT(ASCII(SUBSTRING(version(),%s,1))))%s)and''='";
	public static final String TOOLS_EXPLOIT_BSQLI_BUTTON_OPEVAL_TT = "Insert an OPERATOR and VALUE position marker.\n"
                                                                    + "e.g. 'and((SELECT(ASCII(SUBSTRING(version(),3,1))))<64)and''='\n"
                                                                    + "  -> 'and((SELECT(ASCII(SUBSTRING(version(),%s,1))))%s)and''='";
	public static final String TOOLS_EXPLOIT_BSQLI_BUTTON_VALUE_TT  = "Insert a VALUE position marker.\n"
                                                                    + "e.g. 'and(SELECT ASCII(SUBSTRING(version(),3,1)))BETWEEN 0 and 64 and''='\n"
                                                                    + "  -> 'and(SELECT ASCII(SUBSTRING(version(),%s,1)))BETWEEN 0 and %s and''='";

	public static final String TOOLS_EXPLOIT_BSQLI_POPUP_TITLE_SUFFIX = " - BSQLi";

	public static final String TOOLS_EXPORT_LABEL_MEMO = "Notes";
	public static final String TOOLS_EXPORT_BUTTON_EXPORT_MEMO_TO_TXT_FILE = "Export (.md)";
	public static final String TOOLS_EXPORT_CHECKBOX_FILTER = "Filter";
	public static final String TOOLS_EXPORT_CHECKBOX_FILTER_TT = "Apply filter of List tab to export notes";

	public static final String TOOLS_EXPORT_LABEL_USER_OPTIONS = "User options";
	public static final String TOOLS_EXPORT_BUTTON_USER_OPTIONS_EXPORT = "Export";
	public static final String TOOLS_EXPORT_BUTTON_USER_OPTIONS_EXPORT_TT = "Export user options in json format (exclude: environment-dependent options)";
	public static final String TOOLS_EXPORT_BUTTON_USER_OPTIONS_IMPORT = "Import";
	public static final String TOOLS_EXPORT_BUTTON_USER_OPTIONS_IMPORT_TT = "Import user options (exclude: environment-dependent options)";
	public static final String TOOLS_EXPORT_BUTTON_USER_OPTIONS_CLEAR = "Clear";
	public static final String TOOLS_EXPORT_BUTTON_USER_OPTIONS_CLEAR_TT = "Clear user options and unload ISTE";

	public static final String PROJECT_OPTIONS_PROJECT_NAME = "Project name";
	public static final String PROJECT_OPTIONS_BUTTON_SAVE = "Save";

	public static final String USER_OPTIONS_TEMPLATE_MEMO_BUTTON_SAVE = "Save";
	public static final String USER_OPTIONS_COPY_TEMPLATE_EXPLANATION = "\u2139 Templates for copying to clipboad. This setting adds context menu items of \"ISTE > List\". It uses Apache Velocity 2 as the template engine.";
	public static final String USER_OPTIONS_COPY_TEMPLATE_NAME_TT = "Template name";
	public static final String USER_OPTIONS_COPY_TEMPLATE_MNEMONIC_TT = "Mnemonic";
	public static final String USER_OPTIONS_COPY_TEMPLATE_TEMPLATE_TT = "Template";
	public static final String USER_OPTIONS_USER_NAME = "User name";
	public static final String USER_OPTIONS_DB_FILE_PATH = "Database file";
	public static final String USER_OPTIONS_DB_FILE_BUTTON_SAVE = "Save & Load";
	public static final String USER_OPTIONS_THEME = "Theme";
	public static final String USER_OPTIONS_THEME_EXPLANATION = "* Automatically follow \"User options > Display > User Interface > Theme\".";
	public static final String USER_OPTIONS_USE_KEYBOARD_SHORTCUT = "Shortcut (Send to ISTE)";
	public static final String USER_OPTIONS_USE_KEYBOARD_SHORTCUT_Q = "Enable keyboard shortcut \"Ctrl-Q\", \"Ctrl+Shift-Q\" and \"Ctrl+Alt-Q\" on ProxyHttpHistoryTable.";
	public static final String USER_OPTIONS_USE_KEYBOARD_SHORTCUT_WITH_CLICK = "Enable right-click with \"Ctrl\" or \"Ctrl+Shift\" when ContextMenuCreation.";

	public static final String PLUGINS_BUTTON_ADD_PLUGIN = "Add";
	public static final String PLUGINS_LOAD_FROM_CLASSPATH = "CLASSPATH";

	public static final String ABOUT_BUTTON_CHECK_UPDATE = "Check for updates";
	public static final String ABOUT_CHECKBOX_AUTO_CHECK = "Auto check";
	public static final String ABOUT_CHECKBOX_AUTO_CHECK_TT = "Automatically check for updates on load ISTE";

	public static final String SELECT_PROJECT_NEW = "** Create new project **";
	public static final String CHANGE_DATABASE = "Change DB";


	public static final String MESSAGE_EMPTY = "          ";
	public static final String MESSAGE_SAVED = "Saved.";
	public static final String MESSAGE_DONE = "Done.";
	public static final String MESSAGE_DUPLICATE_UPDATE = "It has already been updated by another window. Override it?";

	public static final String MESSAGE_EXTRACT_ERROR = "**ERROR**";
	public static final String MESSAGE_VERSION_LATEST = "ISTE is up to date.";
	public static final String MESSAGE_VERSION_NOT_LATEST = "%s has been released. Please download and try it!";

	public static final String MESSAGE_CHOOSE_DB_FILE = "Choose SQLite database file for ISTE";
	public static final String MESSAGE_MIGRATION = "Are you sure you want to perform database migration now?";
	public static final String MESSAGE_SELECT_PROJECT = "Select ISTE project";
	public static final String MESSAGE_SELECT_SEND_TO_HISTORY_TARGET = "To which history do you want to add the selected item?";
	public static final String MESSAGE_SELECT_CREATE_CHAIN_TARGET = "To which message create a request chain?";
	public static final String MESSAGE_SELECT_CREATE_CHAIN_TARGET_EXIST = "Selected message has chain. Override it?";
	public static final String MESSAGE_AUTH_CHAIN_EXIST = "Auth chain already exists. Override it?";
	public static final String MESSAGE_SELECT_SEMIAUTO_SETTING_TARGET_COOKIE = "Select transfer target cookies";
	public static final String MESSAGE_SELECT_SEMIAUTO_SETTING_TARGET_COOKIE_EMPTY = "No Cookies.";
	public static final String MESSAGE_SELECT_SEMIAUTO_SETTING_TARGET_TOKEN = "Select transfer target tokens";
	public static final String MESSAGE_SELECT_SEMIAUTO_SETTING_TARGET_TOKEN_NOTE = "* hidden(input) and meta tags are listed as candidates";
	public static final String MESSAGE_SELECT_SEMIAUTO_SETTING_TARGET_TOKEN_EMPTY = "No Tokens.";
	public static final String MESSAGE_INPUT_INVALID_EXTRACT_REGEX = "Regex must include just one group.\n e.g. hoge=([^&]+)&";
	public static final String MESSAGE_INPUT_INVALID_EXTRACT_HTML_TAG = "HTML tag settings must be in \"HTML tag selector;attribute name of value\" format.";
	public static final String MESSAGE_DELETE_ITEM = "Are you sure you want to delete the selected item?";
	public static final String MESSAGE_EXIT_WITHOUT_SAVE = "Edits are not saved. Discard them?";
	public static final String MESSAGE_CHOOSE_EXPORT_FILE = "Export";
	public static final String MESSAGE_CHOOSE_IMPORT_FILE = "Import";
	public static final String MESSAGE_CLEAR_USEROPTIONS = "Are you sure you want to clear all user options?\n"
	                                                     + "\n"
	                                                     + "It includes environment-dependent options, for example, path to the database file. At last, it will unload ISTE.";
	public static final String MESSAGE_CHOOSE_PLUGIN_FILE = "Choose ISTE plugin jar file";

}