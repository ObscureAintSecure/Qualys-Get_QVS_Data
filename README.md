>[!NOTE]
>You need an active Qualys subscription to proceed with the information below

------------------------------------------------

This Python script that will gather the Qualys Vulnerability Score (QVS) details for all the CVE's listed in the associated cve_list.txt file. 

The Qualys API requires input of explicit CVEs to lookup so you can't just tell it to provide all the QVS scores for the entire KB. So this script relies on a reference text file to feed into the API call. 

My script returns six columns of data:  CVE, QVS, QVSLastChangedDate, NVDPublishedDate, CVSS, and CVSSVersion.

![Image of date columns in Unix timestamp format.](date-orig.png)

QVDLastChangedDate and NVDPublishedDate are in Unix timestamp format.  The script I am providing will decode that timestamp to a human readable date.

![Image of date columns converted to human readable format.](date-converted.png)


Scroll down to see an example of running an API query on a single CVE.
--------------------------------------------------

### Determine your API URL

You can get your API URL here: https://www.qualys.com/platform-identification/

Update the "url" line of the script with the correct one for you.

--------------------------------------------------

### BASE64 Encoding Your Username:Password

Your Qualys username and password should be used in the Authorization header field in the script as: 
```
Basic abcDEFghiJKLmnoPQRstuVWXyz012345
```

You can use the online converter https://www.base64encode.org to convert the string

Replace **[BASE64 USER:PASSWORD]** in the script with **[your BASE64 String]**

--------------------------------------------------

### Example for gathering QVS data on an individual CVE via command line

>[!NOTE]
>The Qualys API documentation does not reflect the current approach to executing a curl command in a command line interface (CLI), or terminal session. The API documentation states putting a "-u 'USERNAME:PASSWORD'" but the current requirement is to use "-H 'Authorization: Basic abcDEFghiJKLmnoPQRstuVWXyz012345" to leverage the BASE64 format requirement. 

Here is an example command you can run to get the QVS of CVE-2021-36765:

```
curl -H "Authorization: Basic abcDEFghiJKLmnoPQRstuVWXyz012345" -H "X-Requested-With:curl" "https://[YOUR API URL]/api/2.0/fo/knowledge_base/qvs/?action=list&details=All&cve=CVE-2021-36765"
```

Running that command will return a response like this:

```
{
    "CVE-2021-36765": {
        "base": {
            "id": "CVE-2021-36765",
            "idType": "CVE",
            "qvs": "35",
            "qvsLastChangedDate": 1664755200,
            "nvdPublishedDate": 1628086500
        },
        "contributingFactors": {
            "cvss": "7.5",
            "cvssVersion": "v3.x",
            "cvssString": "AV:N\/AC:L\/PR:N\/UI:N\/S:U\/C:H\/I:N\/A:N"
        }
    }
}
```