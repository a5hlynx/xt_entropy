# Shannon Entropy X-Tension

A X-Tension for X-Ways Forensics, which calculates Shannon Entropy for each item.

## Build

Open xt_entropy.sln and Build solution for the desired platform. xt_entropy.dll will be created at the path below. The solution is confirmed to be built by Visual Studio 2019.
* x86
  * xt_entropy\Release\xt_entropy.dll
* x64
  * xt_entropy\x64\Release\xt_entropy.dll

The dll for both x86 and x64 already build are also available at the [release](https://github.com/a5hlynx/xt_entropy/releases).

## Usage
This X-Tension can be executed either from Refine Volume Snapshot or from Directory Browser Context Menu.
* Refine Volume Snapshot
  1. Click "Refine Volume Snapshot..." in "Specialist" from the Menu bar.
  2. Check "Run X-Tensions" and click "..." in the "Refine Volume Snapshot" Window.
  3. Select xt_entropy.dll in the "Run X-Tensions" Window.
* Directory Browser
  1. Right-Click on the target items in the Directory Browser and choose "Run X-Tensions...".
  2. Select xt_entropy.dll in the "Run X-Tensions" Window.

The calculation result for each item is stored into "Comments" field.

## Requirements
xt_entropy.dll is confirmed to work with X-Ways Forensics 19.9 installed on x64 Windows 10.

## License
GNU Affero General Public License v3.0.

## Documentation
The usage Example is posted at https://9ood4nothin9.blogspot.com/2020/01/shannon-entropy-x-tension.html
