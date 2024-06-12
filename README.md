# Behavior Speaks Louder: Rethinking Malware Analysis Beyond Family Classification

## AMBL

The AMBL folder contains the code and dependent files (Malicious Behaviors Mapped APIs,Label Related Sensitive APIs) used by the AMBL framework to generate malware reports for malware.

To run this code, you first need to follow the dependencies described in *requirement. txt*.

Then you can obtain the details of running the code through the *Python main.py -- help* command

```
usage: main.py [-h] --apk_sha256 APK_SHA256 --apk_path APK_PATH
               [--output_path OUTPUT_PATH] [--Permission PERMISSION] [--API API]
               [--Intent INTENT] [--Function_call_graph FUNCTION_CALL_GRAPH]
               [--Malicious_label MALICIOUS_LABEL] [--Malware_report MALWARE_REPORT]

optional arguments:
  -h, --help            show this help message and exit
  --apk_sha256 APK_SHA256
                        SHA256 of the malware
  --apk_path APK_PATH   The file path of malware
  --output_path OUTPUT_PATH
                        output path
  --Permission PERMISSION
                        Print permissions used by the malware
  --API API             Print APIs used by the malware
  --Intent INTENT       Print intents used by the malware
  --Function_call_graph FUNCTION_CALL_GRAPH
                        Generate the function call graph for malware, with the output file
                        ending in a. gml suffix
  --Malicious_label MALICIOUS_LABEL
                        Print the malicious labels of the malware
  --Malware_report MALWARE_REPORT
                        Generate the malware report for the malware
```

Here is an example of the command to generate a malware report: 

```
python main.py --apk_sha256 4fe0bc6ec7c284b92f6e45aca7ea7972d1b60a913f2af884dd79b03cd2add610 --apk_path ./res/4fe0bc6ec7c284b92f6e45aca7ea7972d1b60a913f2af884dd79b03cd2add610/4fe0bc6ec7c284b92f6e45aca7ea7972d1b60a913f2af884dd79b03cd2add610 --output_path ./res/4fe0bc6ec7c284b92f6e45aca7ea7972d1b60a913f2af884dd79b03cd2add610/ --Malware_report
```



## Dataset

The Dataset folder contains the dataset we have constructed, which contains 1000 corresponding malware reports and can be directly used by other work based on machine learning detection research.
