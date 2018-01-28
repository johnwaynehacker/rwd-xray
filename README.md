# rwd-xray
Honda/Acura calibration file (rwd) firmware extractor

NOTE THAT THIS IS A WORK IN PROGRESS AND MAY NOT OUTPUT VALID FIRMWARE YET

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

## .rwd File Formats
Each file has a signature, headers, and firmware

---

### Z (0x5a) format
##### STATUS: high priority (many files use this format)
- [x] signature
- [ ] headers
    - [ ] encryption keys - are they in the 6th header?
- [ ] firmware
    - [ ] cipher - firmware is most likely encrypted
    - [ ] checksums - need to find some to validate
    - [ ] first 8 bytes - different, so what are they?

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
| ...                 |
| (repeat)            |
| ...                 |
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
TBD

---

### 1 (0x31) format
##### STATUS: high priority (many files use this format)
- [x] signature
- [x] headers
    - [x] encryption keys
- [ ] firmware
    - [x] cipher
    - [ ] checksums - validated for 39990-TV9-A910, can we generalize for all files?
    - [ ] last 4 bytes - different, what are they?

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
| ...                       |
| (repeat)                  |
| ...                       |
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
|    |DDDDDDDDDDDDDDDD|
+----+----------------+
```

|label|bytes|description|
|----:|----:|-----------|
|A|4|address >> 4|
|D|128|data|

---

### X (0x58) format
##### STATUS: low priority (very few files in this format)
- [x] signature
- [ ] headers
- [ ] firmware

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
##### STATUS: low priority (very few files in this format)
- [x] signature
- [ ] headers
- [ ] firmware

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
##### STATUS: low priority (very few files in this format)
- [x] signature
- [ ] headers
- [ ] firmware

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

credit goes to george hotz for reverse engineering the firmware encoding
