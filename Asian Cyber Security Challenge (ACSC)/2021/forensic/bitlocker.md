# BitLocker Artifact

## Description

- Download file: [link](https://drive.google.com/file/d/1kqYvfr3m0vihigvarV3xRBeuGEOTDZYB/view?usp=sharing)

```
Get the datetime that C drive was encrypted by BitLocker!
Start: When the BitLocker Wizard was run (UTC+0, YYYY-MM-DD_HH:MM:SS)
End: When encryption was completed by BitLocker (UTC+0, YYYY-MM-DD_HH:MM:SS)
Flag: ACSC{Start_End}
ex: ACSC{2021-05-06_12:00:01_2021-05-06_12:53:11}
```

## Solution

### Brief

The target is to identify the **start** and **end** timestamp of Bitlocker in registry hives.

Refer to [this tweet](https://twitter.com/0gtweet/status/1418322629996564480), to view the timestamp, we need to go to `\SYSTEM\CurrentControlSet\Control\FVEStats\`.

The start time is `OsvEncryptInit` and end time gonna be `OsvEncryptComplete`.

### Details

To view the registry, use `Registry Viewer` of **AccessData** or `Registry Explorer/RECmd` of [**ericzimmerman**](https://ericzimmerman.github.io/#!index.md).

Open **SYSTEM** file in the tool (*In my case it's `Registry Viewer`*). Locate to `\SYSTEM\ControlSet001\Control\FVEStats\`

![image](https://user-images.githubusercontent.com/61876488/135738458-f9b6a8c3-8c5d-408a-b04c-006260cff279.png)

- **Start time**: **132741897867405652**
- **End time**: **132741901078561213**

To convert windows timestamp to UTC time

```PowerShell
PS C:\> [datetime]::FromFileTimeUTC("132741897867405652")
Monday, August 23, 2021 10:56:26 AM
PS C:\> [datetime]::FromFileTimeUTC("132741901078561213")
Monday, August 23, 2021 11:01:47 AM
```
Credit from [n3ddih](https://github.com/n3ddih/Forensics-CTF-Writeups/blob/main/registry/Bitlocker/README.md).
