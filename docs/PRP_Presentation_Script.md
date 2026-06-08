# PRP Presentation Script
## Security Analysis of Token and Session Handling in Modern Web Applications
**Total time: ~8 minutes content + 2 minutes buffer**

---

## Slide 1 — Title (0:30)

"Good morning / afternoon everyone. My name is Andrii Kolodyazhniy, and my Personal Research Project is about the security of token and session handling in modern web applications.

The topic comes from a gap that I noticed in practice: most developers focus on making authentication work correctly, but the layer *after* login — how sessions are stored, how cookies are configured, how logout actually works — is where most of the real vulnerabilities live.

My hook for this project is: *authentication is correct, but session handling is not.*"

---

## Slide 2 — Research Questions (0:40)

"The main research question I set out to answer is: how secure is token and session handling in modern web applications, and which implementation choices create or reduce vulnerabilities?

To answer that, I broke it down into five sub-questions — you can read them on the right. They go from identifying the most common vulnerabilities, through how they are exploited in practice, which scenarios are realistic to test, what their impact is on the CIA triad, and finally which fixes are most effective.

For scope: I built a small but realistic Flask proof-of-concept running in Docker, with two configuration profiles — one deliberately insecure, one hardened — and studied four attack scenarios."

---

## Slide 3 — DOT Framework (0:45)

"For my research methodology I used the DOT framework, which requires at least one method from each of five categories.

For Library, I reviewed OWASP guidance, two RFCs, and the MDN browser security documentation — this gave me the theoretical foundation and answered questions one through three and five.

For Field, I had a consultation with my supervisor to validate the scenario selection and the evidence collection approach.

For Lab, I built and tested the proof of concept — this is where the actual attack demonstrations and comparisons happened.

Showroom was the comparative evaluation between the insecure and secure profiles, and Workshop was a peer design review session with two fellow students.

The Library method covers the most sub-questions, which is why the literature research is the first thing I discuss before the PoC."

---

## Slide 4 — Library Research Findings (0:35)

"The literature review produced four key findings, one for each sub-question it covers.

Finding one: the OWASP ASVS identifies four specific vulnerability classes at the L1 level — meaning the baseline that any public application must pass — and all four appear in OWASP Top 10 A07:2021.

Finding two: the root causes are in published standards. RFC 6265 explicitly states that cookies are insecure by default without certain attributes, and RFC 7519 defines JWTs as stateless tokens that remain valid until expiry unless you build revocation on top.

Finding three: the OWASP Testing Guide has standard test cases — OTG-SESS-002 through -009 — that confirm each of my four scenarios is realistic and reproducible in a lab environment.

And finding four: the same OWASP cheat sheets that describe the problems also specify four baseline fixes that are low-complexity and high-impact — I'll come back to those at the end."

---

## Slide 5 — PoC Architecture (0:25)

"The proof of concept is a minimal but realistic web application. It has a browser talking to a Flask backend talking to SQLite, nothing more.

What makes it useful for research is the two configuration profiles. InsecureConfig deliberately enables all four vulnerabilities. SecureConfig applies the fixes. Switching between them is a single config class change — same code, same routes, same templates — so the comparison is clean.

The cookie-session path is where scenarios S1 and S2 live, and the JWT bearer path is where S3 and S4 live."

---

## Slide 6 — S1 + S2 Before / After (1:10)

"Now the lab evidence. Each scenario has a before and after column.

**S1 — missing cookie flags.** On the left you can see the DevTools Application tab in insecure mode: no Secure flag, no HttpOnly, no SameSite. This means the session cookie travels over plain HTTP — anyone on the same network can capture it with tcpdump — and it is readable from JavaScript via document.cookie. On the right, after the fix, you can see all three flags applied. The cookie is gone from HTTP traffic and document.cookie returns an empty string.

**S2 — session fixation.** The attack works because the session ID does not change when the user logs in. An attacker who plants a session ID in the victim's browser before login ends up owning the same session after login. You can see the cookie value is identical before and after. On the right, the secure version: a new session ID is issued on every login. The planted ID becomes an orphan — it points to a deleted server-side file."

---

## Slide 7 — S3 + S4 Before / After (1:10)

"**S3 — XSS token theft.** This is the most impactful scenario. In insecure mode the JWT is stored in localStorage, and the notes field renders content without escaping. An attacker posts a one-line script tag as a note. When any logged-in user views the dashboard, their browser executes the script, reads the token from localStorage, and sends it to the attacker's server. You can see the actual captured token in tokens.log with timestamp and source IP.

On the right in secure mode: localStorage.getItem returns null because the token is now in an HttpOnly cookie. And even if a script tag somehow ran, the Content Security Policy header — default-src 'self' — blocks the fetch call to any external origin.

**S4 — broken logout.** In insecure mode, logout only tells the client to discard the token. The server has no record of it, so a captured token continues to return HTTP 200 with full account data after logout. You can see that in the terminal output on the left.

On the right: after the fix, the same token immediately returns HTTP 401 with the message 'Token has been revoked'. The server added the token's jti to a deny-list at logout and checks it on every request."

---

## Slide 8 — Comparative Results Table (0:55)

"Here is the full comparison across all four scenarios.

The INSECURE column shows the observed attacks: cookie captured in plaintext, session takeover, JWT logged by the attacker server, HTTP 200 after logout.

The SECURE column shows that every single attack failed. Cookie not in traffic, planted session ID orphaned, localStorage returns null, HTTP 401 after logout.

The residual risk column is honest about what remains: HTTPS transport is required for the Secure flag to matter, and the jti deny-list in SQLite would need to move to Redis for a high-traffic production environment. But within the defined scope of this research, all risks drop to LOW or VERY LOW."

---

## Slide 9 — CIA + Risk Analysis (0:30)

"The CIA analysis is consistent across all four scenarios: Confidentiality HIGH, Integrity HIGH, Availability LOW. Every vulnerability results in full account takeover — the attacker can read and modify all account data. None of the attacks disrupts service availability on its own.

The risk table on the right shows the reduction in risk level. The most severe is S3, rated CRITICAL in the insecure profile because the XSS sink is present and the attack requires a single line of JavaScript with no specialised tools. After applying the secure controls, it drops to LOW.

The bottom line: approximately ten lines of code, no new dependencies, risk reduced across the board."

---

## Slide 10 — Answers to Research Questions (0:50)

"Let me answer the sub-questions directly.

Q1 — the most common vulnerabilities are the four I studied: missing cookie flags, session fixation, JWT in localStorage, absent server-side revocation. All are OWASP ASVS L1 findings.

Q2 — exploitation paths: passive network sniffing for S1, a one-line XSS payload for S3, and a simple curl command replaying a captured token for S4. No specialised tools needed for any of them.

Q3 — all four scenarios are realistic and feasible, confirmed by the OWASP Testing Guide and reproduced in the lab with only browser DevTools, tcpdump, and curl.

Q4 — CIA impact: HIGH on confidentiality and integrity, LOW on availability, for every scenario.

Q5 — the most effective fixes, in order of effort: set three cookie flags in config, call session.clear on login, use an HttpOnly cookie instead of localStorage, add a jti deny-list. That is the full answer to the main research question: the vulnerabilities come from accepting framework defaults without reviewing their security implications, and the fixes require only configuration and about ten lines of code."

---

## Slide 11 — Body of Knowledge + Questions (0:20)

"Finally, the BoK subjects I applied in this project.

1.2 — Threat and Risk Analysis with CIA: directly applied in the CIA table and the OWASP risk matrix.

1.4 — Law, Ethics, and Responsible Disclosure: all experiments stayed within the self-built PoC, and I referenced the NCSC responsible disclosure guideline throughout.

1.7 — XSS and CSRF: scenario S3 is a stored-XSS attack, and SameSite cookies plus CSP address the CSRF and exfiltration aspects.

1.8 — Network Scanning and Sniffing: scenario S1 is a passive sniffing attack using tcpdump on the Docker bridge network.

1.10 — Secure Remote Access: the Secure cookie flag and HSTS header both enforce HTTPS transport, which is where RFC 6265 compliance starts.

That's the presentation. I'm happy to take any questions."

---

## Timing summary

| Slide | Topic | Time |
|-------|-------|------|
| 1 | Title | 0:30 |
| 2 | Research questions | 0:40 |
| 3 | DOT framework | 0:45 |
| 4 | Library research | 0:35 |
| 5 | PoC architecture | 0:25 |
| 6 | S1 + S2 before/after | 1:10 |
| 7 | S3 + S4 before/after | 1:10 |
| 8 | Comparative results | 0:55 |
| 9 | CIA + risk | 0:30 |
| 10 | Answers + conclusion | 0:50 |
| 11 | BoK + Q&A | 0:20 |
| **Total** | | **~8:00** |

---

## Tips

- **Slide 6 and 7** are the most time-sensitive. Practise narrating each before/after pair in exactly 15–20 seconds per scenario.
- **Do not read from the slides.** The slides show evidence; you explain what it means.
- **Slide 7 S3** is the strongest moment — pause briefly after mentioning tokens.log and let the audience read the captured JWT on screen before moving on.
- **Slide 10** is the payoff — you are directly answering the questions the audience read on slide 2. Make the connection explicit: "remember the five questions from slide two — here are the answers."
