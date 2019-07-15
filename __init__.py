import os
import json

from binaryninja import PluginCommand, BackgroundTaskThread, BinaryViewType, Settings, log_info

from .src import FormatStringFinder
from .tests import run_fs_tests

__all__ = []

# ====================
# Settings
# Register group
group_id = "format_string_finder"
Settings().register_group(group_id, "Format String Finder")

# Register setting 1
setting_1_id = "should_highlight_variable_trace"
setting_1_should_highlight_variable_trace = group_id + "." + setting_1_id
setting_1_properties = {
    "description":
    "Highlight instructions that are used in the trace of the format parameter origin.",
    "title": "Should Highlight Variable Trace",
    "default": False,
    "type": "boolean",
    "id": setting_1_id
}
Settings().register_setting(setting_1_should_highlight_variable_trace, json.dumps(setting_1_properties))

# Register setting 2
setting_2_id = "should_enable_tests_plugin"
setting_2_should_enable_tests_plugin = group_id + "." + setting_2_id
setting_2_properties = {
    "description": "Enable the tests plugin. Only for development.",
    "title": "Should Enable Tests Plugin",
    "default": False,
    "type": "boolean",
    "id": setting_2_id
}
Settings().register_setting(setting_2_should_enable_tests_plugin, json.dumps(setting_2_properties))


# ====================
# Plugins
class RunPluginInBackground(BackgroundTaskThread):
    def __init__(self, func, *args):
        BackgroundTaskThread.__init__(self, f"Running {func.__name__}", can_cancel=True)
        self.func = func
        self.args = args

    def run(self):
        self.func(*self.args)


# ====================
# find format strings plugin
def plugin_fs_finder(bv):
    # Find format strings
    fs_finder = FormatStringFinder(bv, Settings().get_bool(setting_1_should_highlight_variable_trace))
    fs_finder.find_format_strings()

    # Get results and print them in the logs view and in a markdown report
    md = fs_finder.get_results_string()
    log_info(md)

    md = '<span style="color:red">(use the \'Log View\' for clickable addresses)</span>\n' + md
    title = f"FormatStringFinder results for {os.path.basename(bv.file.filename)}"
    bv.show_markdown_report(title=title, contents=md)


def run_plugin_fs_finder(*args):
    t = RunPluginInBackground(plugin_fs_finder, *args)
    t.start()


PluginCommand.register("Format String Finder", "Finds format string vulnerabilities", run_plugin_fs_finder)


# ====================
# find format strings **test** plugin
def run_fs_tests_in_background(*args):
    t = RunPluginInBackground(run_fs_tests, *args)
    t.start()


# Only enable the **tests** plugin if the setting is enabled
if Settings().get_bool(setting_2_should_enable_tests_plugin):
    PluginCommand.register(
        "Format String Finder: Run Tests", "Test format-string-finder", run_fs_tests_in_background
    )
