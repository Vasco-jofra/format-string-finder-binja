# Format String Finder
Author: **jofra**

_Finds format string vulnerabilities_

## Description:
This plugin will detect format string vulnerabilities and printf-like functions.

## Example
![](https://raw.githubusercontent.com/Vasco-jofra/format-string-finder-binja/master/images/example.gif)

## How it works
 1. Loads [known functions](https://raw.githubusercontent.com/Vasco-jofra/format-string-finder-binja/master/src/data/default_printf_like_functions.data) that receive a format parameter.
 2. For each xref of these functions find where the fmt parameter comes from:
    1. If it comes from an **argument** we mark it as a **printf-like function** and test its xrefs
    2. If it is a **constant** value located in a **read-only** area we mark it as **safe**
    3. If it comes from a known **'safe' function call result** (functions from the `dgettext` family) we mark it as **safe**
    4. Otherwise we mark it as **vulnerable**
 3. Prints a markdown report

## Settings
 - `format_string_finder.should_highlight_variable_trace`:
   - Highlight instructions that are used in the trace of the format parameter origin.
 - `format_string_finder.should_enable_tests_plugin`
   - Enable the tests plugin. Only for development.
