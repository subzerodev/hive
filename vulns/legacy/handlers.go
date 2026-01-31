// vulns/legacy/handlers.go
package legacy

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// Flash cross-domain policy
		handlers.Handle("/vulns/legacy/flash/crossdomain", flashCrossDomain)
		handlers.Handle("/vulns/legacy/flash/crossdomain-restrictive", flashCrossDomainRestrictive)

		// Silverlight cross-domain policy
		handlers.Handle("/vulns/legacy/silverlight/clientaccesspolicy", silverlightPolicy)
		handlers.Handle("/vulns/legacy/silverlight/clientaccesspolicy-restrictive", silverlightPolicyRestrictive)

		// ASP.NET ViewState
		handlers.Handle("/vulns/legacy/viewstate/without-mac", viewstateWithoutMAC)
		handlers.Handle("/vulns/legacy/viewstate/with-mac", viewstateWithMAC)
		handlers.Handle("/vulns/legacy/viewstate/encrypted", viewstateEncrypted)

		// Perl code injection (simulated)
		handlers.Handle("/vulns/legacy/perl/eval", perlEval)
		handlers.Handle("/vulns/legacy/perl/open", perlOpen)

		// Ruby code injection (simulated)
		handlers.Handle("/vulns/legacy/ruby/eval", rubyEval)
		handlers.Handle("/vulns/legacy/ruby/erb", rubyERB)

		// Python code injection (simulated)
		handlers.Handle("/vulns/legacy/python/eval", pythonEval)
		handlers.Handle("/vulns/legacy/python/exec", pythonExec)

		// Generic/Unidentified code injection
		handlers.Handle("/vulns/legacy/code/unidentified", unidentifiedCodeInjection)
	})
}

// Flash Cross-Domain Policy
func flashCrossDomain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, `<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<!-- VULNERABLE: Overly permissive Flash cross-domain policy -->
<cross-domain-policy>
    <allow-access-from domain="*"/>
    <allow-http-request-headers-from domain="*" headers="*"/>
</cross-domain-policy>`)
}

func flashCrossDomainRestrictive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, `<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<!-- SAFE: Restrictive Flash cross-domain policy -->
<cross-domain-policy>
    <site-control permitted-cross-domain-policies="master-only"/>
    <allow-access-from domain="trusted.example.com" secure="true"/>
</cross-domain-policy>`)
}

// Silverlight Cross-Domain Policy
func silverlightPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<!-- VULNERABLE: Overly permissive Silverlight cross-domain policy -->
<access-policy>
    <cross-domain-access>
        <policy>
            <allow-from http-request-headers="*">
                <domain uri="*"/>
            </allow-from>
            <grant-to>
                <resource path="/" include-subpaths="true"/>
            </grant-to>
        </policy>
    </cross-domain-access>
</access-policy>`)
}

func silverlightPolicyRestrictive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<!-- SAFE: Restrictive Silverlight cross-domain policy -->
<access-policy>
    <cross-domain-access>
        <policy>
            <allow-from>
                <domain uri="https://trusted.example.com"/>
            </allow-from>
            <grant-to>
                <resource path="/api/public" include-subpaths="false"/>
            </grant-to>
        </policy>
    </cross-domain-access>
</access-policy>`)
}

// ASP.NET ViewState tests
func viewstateWithoutMAC(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: ViewState without MAC validation
	// This is a simulated ViewState that lacks integrity checking
	viewstateData := map[string]string{
		"UserId":   "1",
		"Username": "admin",
		"Role":     "user",
	}

	// Encode as base64 (simulated ViewState format)
	serialized := fmt.Sprintf("UserId=%s|Username=%s|Role=%s",
		viewstateData["UserId"], viewstateData["Username"], viewstateData["Role"])
	encodedViewState := base64.StdEncoding.EncodeToString([]byte(serialized))

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>ASP.NET ViewState Without MAC</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>ASP.NET ViewState Without MAC Enabled</h1>
<p>ViewState lacks Message Authentication Code (MAC) validation.</p>

<form method="POST" action="#">
    <input type="hidden" name="__VIEWSTATE" value="%s">
    <input type="hidden" name="__VIEWSTATEGENERATOR" value="CA0B0334">
    <button type="submit">Submit</button>
</form>

<h2>ViewState Analysis:</h2>
<pre>
Encoded: %s
Decoded: %s
</pre>

<h3>Vulnerability:</h3>
<p><small>ViewState can be tampered with without MAC validation</small></p>
<p><small>Attacker could modify Role=user to Role=admin</small></p>
<p><a href="/vulns/legacy/">Back</a></p>
</div>
</body></html>`, encodedViewState, encodedViewState, serialized)
}

func viewstateWithMAC(w http.ResponseWriter, r *http.Request) {
	// ViewState with MAC (partial protection)
	viewstateData := "UserId=1|Username=admin|Role=user"
	mac := "HMAC_SHA256_SIGNATURE_HERE"
	encodedViewState := base64.StdEncoding.EncodeToString([]byte(viewstateData + "|MAC:" + mac))

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>ASP.NET ViewState With MAC</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>ASP.NET ViewState With MAC</h1>
<p>ViewState has MAC validation but may still be vulnerable to other attacks.</p>

<form method="POST" action="#">
    <input type="hidden" name="__VIEWSTATE" value="%s">
    <input type="hidden" name="__VIEWSTATEGENERATOR" value="CA0B0334">
    <input type="hidden" name="__EVENTVALIDATION" value="enabled">
    <button type="submit">Submit</button>
</form>

<h3>Security:</h3>
<p><small>MAC provides integrity checking but not confidentiality</small></p>
<p><a href="/vulns/legacy/">Back</a></p>
</div>
</body></html>`, encodedViewState)
}

func viewstateEncrypted(w http.ResponseWriter, r *http.Request) {
	// SAFE: ViewState encrypted and signed
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>ASP.NET ViewState Encrypted</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>ASP.NET ViewState Encrypted</h1>
<p>ViewState is both encrypted and signed.</p>

<form method="POST" action="#">
    <input type="hidden" name="__VIEWSTATE" value="ENCRYPTED_AND_SIGNED_VIEWSTATE_DATA">
    <input type="hidden" name="__VIEWSTATEGENERATOR" value="CA0B0334">
    <input type="hidden" name="__EVENTVALIDATION" value="enabled">
    <button type="submit">Submit</button>
</form>

<h3>Security:</h3>
<p><small>SAFE: ViewStateEncryptionMode=Always provides confidentiality and integrity</small></p>
<p><a href="/vulns/legacy/">Back</a></p>
</div>
</body></html>`)
}

// Perl Code Injection (simulated)
func perlEval(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		code = "print 'Hello World'"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Perl eval() Injection</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Perl Code Injection - eval()</h1>
<p>Simulated Perl eval() injection vulnerability.</p>

<form method="GET">
    <textarea name="code" rows="3" cols="50">%s</textarea><br>
    <button type="submit">Execute</button>
</form>

<h2>Code to Execute:</h2>
<pre>eval("%s");</pre>

<h2>Simulated Output:</h2>
<pre>[Perl execution simulated - code would be: %s]</pre>

<h3>Vulnerability:</h3>
<p><small>User input passed to Perl eval() allows arbitrary code execution</small></p>
<p><a href="/vulns/legacy/">Back</a></p>
</div>
</body></html>`, code, code, code)
}

func perlOpen(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	if file == "" {
		file = "data.txt"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Perl open() Injection</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Perl Code Injection - open()</h1>
<p>Simulated Perl open() command injection.</p>

<form method="GET">
    <input name="file" value="%s" style="width:300px"><br>
    <button type="submit">Open File</button>
</form>

<h2>Perl Code:</h2>
<pre>open(FH, "%s");</pre>

<h2>Attack Example:</h2>
<pre>file=|id</pre>
<p>Pipes command output to the file handle.</p>

<h3>Vulnerability:</h3>
<p><small>Perl two-argument open() allows command injection via pipe</small></p>
<p><a href="/vulns/legacy/">Back</a></p>
</div>
</body></html>`, file, file)
}

// Ruby Code Injection (simulated)
func rubyEval(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		code = "puts 'Hello World'"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Ruby eval() Injection</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Ruby Code Injection - eval()</h1>
<p>Simulated Ruby eval() injection vulnerability.</p>

<form method="GET">
    <textarea name="code" rows="3" cols="50">%s</textarea><br>
    <button type="submit">Execute</button>
</form>

<h2>Ruby Code:</h2>
<pre>eval("%s")</pre>

<h2>Attack Examples:</h2>
<pre>
code=system('id')
code=` + "`" + `id` + "`" + `
</pre>

<h3>Vulnerability:</h3>
<p><small>User input passed to Ruby eval() allows arbitrary code execution</small></p>
<p><a href="/vulns/legacy/">Back</a></p>
</div>
</body></html>`, code, code)
}

func rubyERB(w http.ResponseWriter, r *http.Request) {
	template := r.URL.Query().Get("template")
	if template == "" {
		template = "<%= 7 * 7 %>"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Ruby ERB Injection</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Ruby ERB Template Injection</h1>
<p>Simulated ERB template injection vulnerability.</p>

<form method="GET">
    <input name="template" value="%s" style="width:300px"><br>
    <button type="submit">Render</button>
</form>

<h2>Template:</h2>
<pre>ERB.new("%s").result</pre>

<h2>Attack Examples:</h2>
<pre>
template=&lt;%%= system('id') %%&gt;
template=&lt;%%= File.read('/etc/passwd') %%&gt;
</pre>

<h3>Vulnerability:</h3>
<p><small>User input in ERB templates allows code execution</small></p>
<p><a href="/vulns/legacy/">Back</a></p>
</div>
</body></html>`, template, template)
}

// Python Code Injection (simulated)
func pythonEval(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		code = "2 + 2"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Python eval() Injection</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Python Code Injection - eval()</h1>
<p>Simulated Python eval() injection vulnerability.</p>

<form method="GET">
    <input name="code" value="%s" style="width:300px"><br>
    <button type="submit">Evaluate</button>
</form>

<h2>Python Code:</h2>
<pre>result = eval("%s")</pre>

<h2>Attack Examples:</h2>
<pre>
code=__import__('os').system('id')
code=open('/etc/passwd').read()
</pre>

<h3>Vulnerability:</h3>
<p><small>User input passed to Python eval() allows arbitrary code execution</small></p>
<p><a href="/vulns/legacy/">Back</a></p>
</div>
</body></html>`, code, code)
}

func pythonExec(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		code = "print('Hello World')"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Python exec() Injection</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Python Code Injection - exec()</h1>
<p>Simulated Python exec() injection vulnerability.</p>

<form method="GET">
    <textarea name="code" rows="3" cols="50">%s</textarea><br>
    <button type="submit">Execute</button>
</form>

<h2>Python Code:</h2>
<pre>exec("%s")</pre>

<h2>Attack Examples:</h2>
<pre>
code=import os; os.system('id')
code=import subprocess; subprocess.call(['cat', '/etc/passwd'])
</pre>

<h3>Vulnerability:</h3>
<p><small>User input passed to Python exec() allows arbitrary code execution</small></p>
<p><a href="/vulns/legacy/">Back</a></p>
</div>
</body></html>`, code, code)
}

// Generic/Unidentified Code Injection
func unidentifiedCodeInjection(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		code = "1+1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Unidentified Code Injection</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Unidentified Code Injection</h1>
<p>Generic code injection where the language/interpreter is unknown.</p>

<form method="GET">
    <textarea name="code" rows="3" cols="50">%s</textarea><br>
    <button type="submit">Execute</button>
</form>

<h2>Code Submitted:</h2>
<pre>%s</pre>

<h2>Detection Patterns:</h2>
<ul>
    <li>Mathematical expressions: 1+1, 7*7</li>
    <li>String operations: 'a'+'b', "test".length</li>
    <li>Function calls: system(), exec(), eval()</li>
    <li>Template syntax: ${7*7}, {{7*7}}, &lt;%%= 7*7 %%&gt;</li>
</ul>

<h3>Vulnerability:</h3>
<p><small>User input executed as code in an unidentified interpreter</small></p>
<p><a href="/vulns/legacy/">Back</a></p>
</div>
</body></html>`, code, code)
}
