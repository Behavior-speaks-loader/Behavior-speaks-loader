# Analysis example

Malware: 6b6b6cba2aced9e46829949f2bf023b7301033f56546c6d69d355a34a519dc82

The process of manual analysis is as follows:

1. Starting from sensitive API. For example, API related to location information is as follows:

   ```java
   locationManager.getLastKnownLocation()
   ```

2. Find the method body of the sensitive API:

   ```java
   Location getGPSLocation(Context paramContext){
     if (Util.checkPermission(paramContext, "android.permission.ACCESS_FINE_LOCATION")) {
   …
     return locationManager.getLastKnownLocation("gps");
   }
   ```

3. Search for methods that have a calling relationship with the original method body and determine whether they can form an attack chain. The following related method forms a complete attack chain with the above method of obtaining location information and leaking it to remote servers.

   ```java
   Location param2Location= getGPSLocation(…)
   …
   param1Message = (Message)(param2Location.getCharSequence("sender")).build();
   …
   Return sendMessageAtTime(param1Message,param1Lone)
   ```

4. Based on malicious behavior, determine the malicious labels of the malware, which are Network and Location.

5. Select other sensitive APIs, repeat steps 1-4 above, and finally determine all labels
