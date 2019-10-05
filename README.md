# rwd-xray
Honda/Acura calibration file (rwd) firmware extractor

NOTE THAT THIS IS A WORK IN PROGRESS AND THE ONLY FIRMWARE THAT MAY WORK IS 39990-TV9-A910

### Usage
From a terminal using python 2.x:  
`./rwd-xray.py ./39990-TV9-A910.rwd.gz`

This will output a file containing the firmware named:  
`39990-TV9-A910.bin`

### What are .rwd files?

Part of the Honda Diagnostic System (HDS) software is a tool to flash firmware updates (J2534 Rewrite application) and a set of firmware update files.

The firmeware update files can be found in the directory:  
`C:\Program Files (x86)\Honda\J2534 Pass Thru\CalibFiles`

Each firmware file is named according to the part number  
(usually found printed on outside of the part)  
`MODULE-VEHICLE-VERSION.rwd.gz`

for example, here is a firmware update for a 2016 Acura ILX EPS module:  
`39990-TV9-A910.rwd.gz`

|token|value|description|
|-----|-----|-----------|
|`MODULE`|39990|EPS module|
|`VEHICLE`|TV9|Acura ILX|
|`VERSION`|A910|manufacturer region/code|

See the [File Name Vehicle Reference](./FILENAME_VEHICLE_REFERENCE.md) to see what model and year each rwd file corresponds to.

## .rwd File Formats
Each file has a signature, headers, firmware and checksum

---

### Z (0x5a) format
TODO:
- [x] signature
- [x] headers
    - [x] encryption keys
- [ ] firmware
    - [x] cipher
    - [ ] checksums - need to find some to validate

(many files use this format)

##### SIGNATURE
```
+---+
|S←↓|
+---+
```

|label|bytes|description|
|----:|----:|-----------|
|S|1|signature (0x5a)|
|←↓|2|delimiter (0x0d0a)|

##### HEADERS
```
+-+-+=====+===+-+=====+
|C|L|V...V|...|L|V...V|
+-+-+=====+===+-+=====+
|C|L|V...V|...|L|V...V|
+-+-+=====+===+-+=====+
|C|L|V...V|...|L|V...V|
+-+-+=====+===+-+=====+
|C|L|V...V|...|L|V...V|
+-+-+=====+===+-+=====+
|C|L|V...V|...|L|V...V|
+-+-+=====+===+-+=====+
|C|L|V...V|...|L|V...V|
+-+-+=====+===+-+=====+
```

|label|bytes|description|
|----:|----:|-----------|
|C|1|number of values in header (can be zero)|
|L|1|length header value|
|V|varies|header value (length = preceding L)|

##### FIRMWARE
```
+--------+
|SSSSSSSS|
+--------+
|LLLLLLLL|
+--------+-------+
|DDDDDDDDDDDDDDDD|
| ...            |
| (repeat)       |
| ...            |
|DDDDDDDDDDDDDDDD|
+----+-----------+
```

|label|bytes|description|
|----:|----:|-----------|
|S|8|start address of firmware block|
|L|8|length of firmware block|
|D|varies|data (length = last end of block address)|

##### CHECKSUM
```
+----+
|CCCC|
+----+
```

|label|bytes|description|
|----:|----:|-----------|
|C|4|sum of all bytes in file (excluding these bytes)|

---

### 1 (0x31) format
TODO:
- [x] signature
- [x] headers
    - [x] encryption keys
- [ ] firmware
    - [x] cipher
    - [ ] checksums - validated for 39990-TV9-A910, can we generalize for all files?

(many files use this format)

##### SIGNATURE
```
+---+
|S←↓|
+---+
```

|label|bytes|description|
|----:|----:|-----------|
|S|1|signature (0x31)|
|←↓|2|delimiter (0x0d0a)|

##### HEADERS
```
+---+=======+===+=======+---+
|T←↓|V...V←↓|...|V...V←↓|T←↓|
+---+=======+===+=======+---+
|T←↓|V...V←↓|...|V...V←↓|T←↓|
+---+=======+===+=======+---+
|T←↓|V...V←↓|...|V...V←↓|T←↓|
+---+=======+===+=======+---+
|T←↓|V...V←↓|...|V...V←↓|T←↓|
+---+=======+===+=======+---+
|T←↓|V...V←↓|...|V...V←↓|T←↓|
+---+=======+===+=======+---+
|T←↓|V...V←↓|...|V...V←↓|T←↓|
+---+=======+===+=======+---+
```

|label|bytes|description|
|----:|----:|-----------|
|T|1|type of header|
|V|varies|header value|
|←↓|2|delimiter (0x0d0a)|

##### FIRMWARE
```
+----+----------------+
|AAAA|DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
+----+----------------+
| ...                 |
| (repeat)            |
| ...                 |
+----+----------------+
|AAAA|DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
+----+----------------+
```

|label|bytes|description|
|----:|----:|-----------|
|A|4|address >> 4|
|D|128|data|

##### CHECKSUM
```
+----+
|CCCC|
+----+
```

|label|bytes|description|
|----:|----:|-----------|
|C|4|sum of all bytes in file (excluding these bytes)|

---

### X (0x58) format
TODO:
- [x] signature
- [ ] headers
- [ ] firmware

(very few files in this format)

##### SIGNATURE
```
+---+
|S←↓|
+---+
```

|label|bytes|description|
|----:|----:|-----------|
|S|1|signature (0x58)|
|←↓|2|delimiter (0x0d0a)|

##### HEADERS
TBD

##### FIRMWARE
TBD

---

### Y (0x59) format
TODO:
- [x] signature
- [ ] headers
- [ ] firmware

(very few files in this format)

##### SIGNATURE
```
+---+
|S←↓|
+---+
```

|label|bytes|description|
|----:|----:|-----------|
|S|1|signature (0x59)|
|←↓|2|delimiter (0x0d0a)|

##### HEADERS
TBD

##### FIRMWARE
TBD

---

### 0 (0x30) format
TODO:
- [x] signature
- [ ] headers
- [ ] firmware

(very few files in this format)

##### SIGNATURE
```
+---+
|S←↓|
+---+
```

|label|bytes|description|
|----:|----:|-----------|
|S|1|signature (0x30)|
|←↓|2|delimiter (0x0d0a)|

##### HEADERS
TBD

##### FIRMWARE
TBD

---

credit goes to george hotz for reverse engineering the first firmware cipher
