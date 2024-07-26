# Example of Analysis Process

![case_example](.\case_example.png)



we describe the manual analysis process of malicious software behavior using two examples, divided into four steps:

1. **Initiate from Sensitive APIs**: Initially, we traverse the sensitive APIs directly invoked within the malware(e.g., `SMSMessage.getMessageBody()`), using each sensitive API as the starting point for manual analysis.
2. **Locate the Calling Method**: In the decompiled source code, we identify the method in which the sensitive API is called and analyze the basic functionality of this method.
3. **Determine the Actual Purpose of Sensitive APIs**: Starting from the method identified in step 2, we traverse other methods that have a call relationship with it, and determine the actual purpose of invoking the sensitive API.
4. **Identify Malicious Behavior and Labels**: Based on the actual use of the sensitive API, we determine whether the call constitutes malicious behavior. If it does, we identify which malicious tags it should be associated with.

For the first example (upper part of the figure), (1) starting from the sensitive API `SMSMessage.getMessageBody()`, as the initial point of manual analysis; (2) the method that calls this API is `retrieveMessage()`, whose functionality is to obtain the content of received SMS and return it as a HashMap; (3) then, find the specific usage of the sensitive API in methods that have a calling relationship with `retrieveMessage()`, which in this case is to monitor incoming SMS and execute remote commands when they contain such commands. (4) After determining the specific malicious behavior, select an appropriate malicious behavior label to describe it, which in this case are SMS-related and Overstep-related.

For the second example (lower part of the figure), (1) starting from the sensitive API `LocationManager.getLastKnownLocation()`; (2) the method that calls this API is `getGPSLocation()`, which returns location information; (3) from the `getGPSLocation()` method, find that the usage of the sensitive API is to send it to a remote server to retrieve the weather information for the user's area (`weatherTextView.setText(httpResponse)`); (4) we consider this call to be reasonable, thus it is not considered malicious, and no malicious label is assigned.