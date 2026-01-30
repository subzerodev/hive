package pii

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/info-disclosure/pii/emails", emails)
		handlers.Handle("/vulns/info-disclosure/pii/credit-cards", creditCards)
		handlers.Handle("/vulns/info-disclosure/pii/ssn", ssn)
		handlers.Handle("/vulns/info-disclosure/pii/fp/redacted", fpRedacted)
	})
}

func emails(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Email addresses exposed
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>PII - Emails</title></head>
<body>
<h1>User Directory</h1>
<table border="1">
    <tr><th>Name</th><th>Email</th><th>Role</th></tr>
    <tr><td>John Admin</td><td>john.admin@company.com</td><td>Administrator</td></tr>
    <tr><td>Jane User</td><td>jane.user@company.com</td><td>User</td></tr>
    <tr><td>Bob Support</td><td>bob.support@company.com</td><td>Support</td></tr>
</table>
<p><small>VULNERABLE: Full email addresses exposed</small></p>
</body></html>`)
}

func creditCards(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Credit card numbers exposed
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>PII - Credit Cards</title></head>
<body>
<h1>Payment History</h1>
<table border="1">
    <tr><th>Date</th><th>Card Number</th><th>Amount</th></tr>
    <tr><td>2024-01-15</td><td>4532015112830366</td><td>$99.99</td></tr>
    <tr><td>2024-01-10</td><td>5425233430109903</td><td>$49.99</td></tr>
    <tr><td>2024-01-05</td><td>374245455400126</td><td>$199.99</td></tr>
</table>
<p><small>VULNERABLE: Full credit card numbers exposed</small></p>
</body></html>`)
}

func ssn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Social Security Numbers exposed
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>PII - SSN</title></head>
<body>
<h1>Employee Records</h1>
<table border="1">
    <tr><th>Name</th><th>SSN</th><th>Department</th></tr>
    <tr><td>John Smith</td><td>123-45-6789</td><td>Engineering</td></tr>
    <tr><td>Jane Doe</td><td>987-65-4321</td><td>Marketing</td></tr>
    <tr><td>Bob Wilson</td><td>555-12-3456</td><td>Finance</td></tr>
</table>
<p><small>VULNERABLE: Full Social Security Numbers exposed</small></p>
</body></html>`)
}

func fpRedacted(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	// SAFE: PII properly redacted
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>PII - Redacted</title></head>
<body>
<h1>User Directory (Redacted)</h1>
<table border="1">
    <tr><th>Name</th><th>Email</th><th>Card</th><th>SSN</th></tr>
    <tr><td>John S.</td><td>j***@company.com</td><td>****0366</td><td>***-**-6789</td></tr>
    <tr><td>Jane D.</td><td>j***@company.com</td><td>****9903</td><td>***-**-4321</td></tr>
</table>
<p><small>SAFE: PII properly redacted/masked</small></p>
</body></html>`)
}
