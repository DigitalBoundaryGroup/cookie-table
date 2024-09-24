package dbg.cookietable;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scope.Scope;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;

import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.PersistedList;

import java.util.*;
import java.util.ArrayList;
import java.util.List;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
This is the HTTP Handler class that supports the interface defined in CookieTab.
It reads all in scope responses (to any tool - Proxy, Repeater, etc) and reports the cookies set in those responses to the table.
*/
class CookieScanner implements HttpHandler {
    public static Logging logging;
    public final Scope scope;
    public static ConcurrentSkipListSet<List<String>> cookieTree;
    public static PersistedObject myExtensionData;

    public CookieScanner(MontoyaApi api) {
        this.logging = api.logging();
        this.scope = api.scope();

        // Initialize persistence
        myExtensionData = api.persistence().extensionData();
        PersistedList<String> startupList = myExtensionData.getStringList("cookieList");
        // If no data stored
        if (startupList == null){
            cookieTree = treeSetInit();
        } else {
            cookieTree = treeSetMaker(startupList);
        }
    }
    public static void refresh(){
        CookieTab.retrieveCookieData();
    }

    public static void killTree(){
        cookieTree = treeSetInit();
        refresh();
    }

    public DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MM/dd/yyyy - HH:mm:ss z");

    // Regexes for extracting cookie attributes
    public Pattern secureRegex = Pattern.compile("(\\bsecure\\b)", Pattern.CASE_INSENSITIVE);
    public Pattern httponlyRegex = Pattern.compile("(\\bHttpOnly\\b)", Pattern.CASE_INSENSITIVE);
    public Pattern samesiteRegex = Pattern.compile("\\bSameSite\\s*=\\s*(Lax|Strict|None)\\b", Pattern.CASE_INSENSITIVE);

    public static ConcurrentSkipListSet<List<String>> getCookieData(){
        return cookieTree;
    }
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // What set the cookie?
        String scopeURL = responseReceived.initiatingRequest().url();
        if (scope.isInScope(scopeURL)) { // only report in-scope cookies
            // Get a list of set-cookie header content. This is necessary because Montoya has no builtin for accessing
            // cookie attributes such as secure or HttpOnly.

            List<HttpHeader> headers = responseReceived.headers();
            ArrayList<String> cookieStrings = new ArrayList<>();

            // Get a list of cookie objects from the builtin
            List<Cookie> cookieList = responseReceived.cookies();

            // Check if cookies are set
            if (!cookieList.isEmpty()) {
                for (HttpHeader h: headers){
                    if (h.name().toLowerCase().equals("set-cookie")){
                        cookieStrings.add(h.value()); // make a list of cookies
                    }
                }

                // Get cookie properties
                for (int i = 0; i < cookieList.size(); i++){
                    Cookie httpCookie = cookieList.get(i);

                    ArrayList<String> cookieInfo = new ArrayList<>(); // List to add cookie info to
                    cookieInfo.add(httpCookie.name()); // Cookie name
                    cookieInfo.add(httpCookie.value()); // Cookie value
                    cookieInfo.add(scopeURL); // URL of page that set the cookie

                    if (httpCookie.domain() == null){
                        cookieInfo.add("None");
                    } else {
                        cookieInfo.add(httpCookie.domain());
                    }

                    // Interestingly this removes the . from the start of domain attributes. it's not needed for modern
                    // browsers so I suppose Burp ignores it

                    String expString;

                    Optional<ZonedDateTime> expiration = httpCookie.expiration();
                    if (expiration.isPresent()){
                        ZonedDateTime zdt = expiration.get();
                        expString = zdt.format(formatter);
                    } else {
                        expString = "None";
                    }

                    // ________________

                    cookieInfo.add(expString); // Cookie expiration
                    cookieInfo.add(httpCookie.path()); // Cookie path

                    // Get cookie attributes
                    String httpCookieString = cookieStrings.get(i);

                    // is secure?
                    Matcher secureMatcher = secureRegex.matcher(httpCookieString);
                    if (secureMatcher.find()){
                        cookieInfo.add("Yes");
                    } else {
                        cookieInfo.add("(Not set)");
                    }

                    // is HttpOnly?
                    Matcher httponlyMatcher = httponlyRegex.matcher(httpCookieString);
                    if (httponlyMatcher.find()){
                        cookieInfo.add("Yes");
                    } else {
                        cookieInfo.add("(Not set)");
                    }

                    // is samesite?
                    Matcher samesiteMatcher = samesiteRegex.matcher(httpCookieString);
                    if (samesiteMatcher.find()){
                        // extract what it's set to
                        String sameSite = samesiteMatcher.group(1);
                        cookieInfo.add(sameSite);
                    } else {
                        cookieInfo.add("(Not set)");
                    }

                    cookieTree.add(cookieInfo); // add to treeset
                    myExtensionData.setStringList("cookieList", treeSetCollapse(cookieTree)); // persistence
                    refresh();

                }
            }
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    // Makes a new treeset
    private static ConcurrentSkipListSet<List<String>> treeSetInit() {
        ConcurrentSkipListSet<List<String>> tree = new ConcurrentSkipListSet<>(new CustomComparator());
        return tree;
    }

    // Reads a persisted list into a treeset (for persistence purposes)
    private ConcurrentSkipListSet<List<String>> treeSetMaker(PersistedList<String> l){
        ConcurrentSkipListSet<List<String>> tree = treeSetInit();
        for (String item : l){
            // format: name, value, URL that set it, domain, expiry, path, secure?, httponly?, samesite=value

            String[] substringed = item.split(",");
            ArrayList<String> substringedList = new ArrayList<>(Arrays.asList(substringed));
            tree.add(substringedList);
        }
        return tree;
    }
    // Turns a treeset into a persisted list (for persistence purposes)
    private PersistedList<String> treeSetCollapse(ConcurrentSkipListSet<List<String>> t){
        //PersistedList<String> storageList = PersistedList.persistedStringList();
        ConcurrentSkipListSet<List<String>> modifier = t;
        PersistedList<String> storageList = PersistedList.persistedStringList();
        for (List<String> l : modifier){
            String collapsed = String.join(",", l);
            storageList.add(collapsed);
        }

        return storageList;
    }

    // Custom comparator for the lists
    // format: name, value, URL that set it, domain, expiry, path, secure?, httponly?, samesite=value
    public static class CustomComparator implements Comparator<List<String>>{
        @Override
        public int compare(List<String> list1, List<String> list2) {
            int nameComparison = list1.get(0).compareTo(list2.get(0));
            if (nameComparison != 0) {
                return nameComparison;
            }
            // index from i=3 to avoid comparing different values or urls. only want to compare names and attributes
            for (int i=3; i < list1.size(); i++) {
                if (i==4){
                    // don't check expiry.
                    continue;
                }
                int fieldComparison = list1.get(i).compareTo(list2.get(i));
                if (fieldComparison != 0){
                    return fieldComparison;
                }
            }
            return 0;
        }
    }
}
