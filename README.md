## SysRecon

This is just a python script that will scan your Windows file-system or specific files for known vulnerable drivers using the hashes found in the [Screwed Drivers Repo](https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md).

## But, Why?

So you can know how many vulnerable drivers you have on your PC and also not spend time bughunting on them since they're already known vulnerable (unless you want to find harder/new bugs).

## Usage

### Scan One Driver
`python SysRecon.py -s example.sys`

### Scan List of Drivers (New-line Separated)
`python SysRecon.py -f list.txt`

### Scan Entire File-system from C:\ for Drivers
`python SysRecon.py -r`
