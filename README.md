# WAFDetect

Burp app that passively detects WAF presence from HTTP responses.

## Current features
* Run in the background and create passive scanner issues when WAF traces are detected.
* Use Regex approach to search for matches in HTTP responses
* Support searches in the headers only or in the whole response
* Use separate keyword to highlight responses 

## TODO
* Add more WAF fingerprints/keywords
* Externalize configuration of WAF detections
* Integrate external research if possible

Status: In development
