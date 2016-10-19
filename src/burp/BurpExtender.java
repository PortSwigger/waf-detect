/*
 * Burp WAFDetect extension
 */
package burp;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.*;
import java.io.PrintWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.csv.*;

public class BurpExtender implements IBurpExtender, IScannerCheck
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private static final String EXT_NAME = "WAFDetect";
    private static HashMap wf = new HashMap(); 
    private PrintWriter stdout;
    private PrintWriter stderr;
    private static List<WafFingerprint> wafFingerprints = new ArrayList<WafFingerprint>();
    private static final String FP_FILENAME = "WafFingerprints.csv";   
    private static final Boolean debug = false;
    private static final Boolean info = true;
    
    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {                
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // Set extension name
        callbacks.setExtensionName(EXT_NAME);

        // Obtain output and error streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        
        // Write messages to output streams
        stdout.println("Started " + EXT_NAME);
        //callbacks.issueAlert("Started " + EXT_NAME);

        // Load the WAF fingerprints from external file (in JAR file)
        loadWafFingerprints();
        stdout.println("DEBUG: Fingerprints loaded: " + wafFingerprints.toString());
        
        // Register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);
    }
    
    // helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, byte[] match, int maxOffset)
    {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length)
        {
            start = helpers.indexOf(response, match, true, start, maxOffset);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }
        
        return matches;
    }

    // implement IScannerCheck
    
    /**
     * Listen to HTTP traffic and identify WAF fingerprints
     * @param baseRequestResponse
     * @return "WAF Detected" as can issue logs
     */
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        // Issue list to send to Burp as passive findings
        List<IScanIssue> issues = new ArrayList<>(0);
        
        //Iterator it = wf.entrySet().iterator();
        Iterator<WafFingerprint> it = wafFingerprints.iterator();
        while (it.hasNext()) {
            WafFingerprint wfp = (WafFingerprint)it.next();            
            //if (debug) stdout.println("DEBUG: Passive scan for WAF " + wfp.wafType + " (regex=" + wfp.regex + ")");
            
            // Get HTTP response
            byte[] response      = baseRequestResponse.getResponse();
            String responseTxt   = helpers.bytesToString(response);
            URL url           = helpers.analyzeRequest(baseRequestResponse).getUrl();
            
            // Get the offset for the body and use it if HEADER_ONLY search is specified
            int maxOffset = response.length;
            if (wfp.header){
                maxOffset = helpers.analyzeResponse(response).getBodyOffset();
            }

            // Perform a REGEX search
            Pattern p = Pattern.compile(wfp.regex, Pattern.MULTILINE);
            Matcher m = p.matcher(responseTxt.substring(0, maxOffset));
            if (m.find()){
                if (info) stdout.println("INFO: Match for WAF " + wfp.wafType + " at " + url.toString() + " (regex=" + wfp.regex + ";within " + maxOffset + " bytes of " + response.length + " bytes total)");
                        
                // look for matches of our passive check keyword
                List<int[]> matches = getMatches(response, helpers.stringToBytes(wfp.keyword), maxOffset);
                if (matches.size() > 0){
                    // report the issue
                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            url, 
                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) }, 
                            "WAF Detected: " + wfp.wafType,
                            "Fingerprint Details:" + wfp.describe(), 
                            "Information"));
                    if (info) stdout.println("INFO: Adding informational finding for WAF " + wfp.wafType + " (if not already present)");
                }         
                it.remove(); // avoids a ConcurrentModificationException
            }                
        }   
        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        return null;
    }


    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        // This method is called when multiple issues are reported for the same URL 
        // path by the same extension-provided check. The value we return from this 
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues
        if ((existingIssue.getIssueName().equals(newIssue.getIssueName())) &&
            (existingIssue.getUrl().equals(newIssue.getUrl())) &&
            (existingIssue.getIssueDetail().equals(newIssue.getIssueDetail())))
            return -1;
        else return 0;
    }
    
    /**
     * Load WAF fingerprints from CSV file to simplify addition of new ones 
     */
    private void loadWafFingerprints(){
        InputStream is = this.getClass().getClassLoader().getResourceAsStream(FP_FILENAME);
        try {
            InputStreamReader in = new InputStreamReader(is);
            Iterable<CSVRecord> records = CSVFormat.DEFAULT.withFirstRecordAsHeader().parse(in);
            for (CSVRecord record : records) {
                String waf = record.get("WAF_NAME").trim();
                String kw  = record.get("KEYWORD").trim();
                String re  = record.get("REGEX").trim();
                String hdr = record.get("HEADER_ONLY").trim();
                String ref = record.get("REFERENCE").trim();
                String dsc = record.get("DESCRIPTION").trim();
                wafFingerprints.add(new WafFingerprint(waf,kw, re, Boolean.valueOf(hdr), ref, dsc));
            }
        } catch (IOException ex) {
            ex.printStackTrace(stderr);
        }        
    }
}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url, 
            IHttpRequestResponse[] httpMessages, 
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }
    
    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return null;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }
    
}

/**
 * WAF Fingerprint: Embedded class to hold information about WAF fingerprints to search for
 * @author epaquet
 */
class WafFingerprint{
    String  wafType; 
    String  keyword; 
    String  regex;
    String  ref;
    String  descr;
    Boolean header; 
    
    /**
     * Create WAF Fingerprint object
     * @param wafType   Type of WAF to show in issue description
     * @param keyword   Keyword to search for when highlighting text in HTTP Response
     * @param regex     Regex to search for when checking for a WAF fingerprint
     * @param header    Boolean to specify if only the HTTP response header should be analyzed
     * @param ref       Reference information about where the WAF fingerprint research came from
     * @param descr     Description for the WAF technology
     */
    public WafFingerprint(String wafType, String keyword, String regex, Boolean header, String ref, String descr){
        this.wafType = wafType;
        this.keyword = keyword;
        this.regex   = regex;
        this.header  = header;
        this.ref     = ref;
        this.descr   = descr;
    }

    @Override
    public String toString() {
        String val = "";
        val += "\n" + wafType;
        val += "\t\t("   + header.toString() + ")";
        //val += "\tkeyword=" + keyword;
        val += "\t\t("   + regex + ")";
        return val;
    }

    public String describe() {
        String val = "\n";
        val += "\nWAF Type            : " + wafType;
        val += "\nWAF tech. details   : " + descr;
        val += "\nReference           : " + ref;
        val += "\nMatching regex      : " + regex;
        val += "\nHighlighting keyword: " + keyword;
        val += "\nHeader-only search? : " + header.toString();
        return val;
    }
}