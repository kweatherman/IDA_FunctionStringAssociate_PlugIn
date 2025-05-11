# Function String Associate IDA Pro Plug-In

Kevin Weatherman aka "Sirmabus"
Repo [Github](https://github.com/kweatherman/IDA_FunctionStringAssociate_PlugIn), former: [SourceForge](https://sourceforge.net/projects/idafunctionstringassociate/)

An IDA Pro plugin that automatically adds comments to functions based on the strings they reference.

----
## Overview

The Function String Associate plugin is designed to aid reverse engineering in IDA Pro by extracting meaningful strings (e.g., asserts, variables, constants) from functions and adding them as function comments. This is particularly useful when analyzing large binaries with thousands of functions.   
By browsing these auto-generated comments, you can gain insights into a function's purpose or the context it belongs to.

The usefulness of the plugin depends on the target binary. Some binaries contain many informative strings, resulting in rich comments, while others may have few or none, yielding minimal output.

## Features

- Automatically extracts string references from functions in an IDA database (IDB).
- Sorts strings based on assumed relevance.
- Adds extracted strings as function comments for easy browsing.
- Helps identify function purposes and relationships in complex binaries.

## Installation

- #### Copy the Plugin:

   - Place the plugin file (`IDA_FunctionStringAssociate_PlugIn.dll`) into your IDA Pro plugins directory.

- #### Configure the Plugin:

   - Edit your "plugins.cfg" file to add a hotkey for the plugin.

     Example entry:

     `FunctionStringAssociate IDA_FunctionStringAssociate_PlugIn.dll Alt-6 0`
   
   - Refer to the [official IDA Pro documentation](https://www.hex-rays.com/products/ida/support/) for detailed instructions on installing and configuring plugins.

## Usage

- #### Run the Plugin:

   - Use the assigned hotkey (e.g., Alt-6) or navigate to Edit -> Plugins -> Function String Associate in the IDA Pro menu.

- #### View Results:

   - The plugin will process the IDB and add comments to functions containing string references.
   - Browse functions in IDA to see the generated comments, which may provide clues about each function's role.

## How It Works

The plugin operates as follows:

1. Iterates through every function in the loaded IDA database (IDB).
2. Analyzes each function's elements to identify references to strings.
3. Sorts the strings based on heuristic assumptions about their relevance.
4. Adds the sorted strings as a comment to the respective function.


----

##### License

**MIT License**
Copyright © 2009–present Kevin Weatherman  

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

See [MIT License](http://www.opensource.org/licenses/mit-license.php) for full details.