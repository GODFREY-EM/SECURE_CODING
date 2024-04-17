
6.12 Exploiting Insecure Code Practices


Protego Security Solutions

Because most university computer science departments do not emphasize security in their software development courses, many developers, especially new graduates, are unaware of their role in preventing cybersecurity incidents.

While organizations may use some sort of source code and binaries pre-deployment security scanning, unless developers are directly involved in remediating their own insecure practices, they are likely to repeat their mistakes.

Some software development organizations the use DevOps practices include automated source code scanning every time developers’ work is committed to a code repository and every time binaries are submitted to build repositories. This enables what is called a shift-left approach to software security in which developers take an active responsibility for enhancing security in their own code based on feedback from these scanners.

We can only hope! We have not been informed of how Pixel Paradise ensures that their code is developed with security in mind, but we will find out!

The following sections cover several insecure code practices that attackers can exploit and that you can leverage during a penetration testing engagement.

6.12.2 Comments in Source Code

Often developers include information in source code that could provide too much information and might be leveraged by an attacker. For example, they might provide details about a system password, API credentials, or other sensitive information that an attacker could find and use.

NOTE MITRE created a standard called the Common Weakness Enumeration (CWE). The CWE lists identifiers that are given to security malpractices or the underlying weaknesses that introduce vulnerabilities. CWE-615, “Information Exposure Through Comments,” covers the flaw described in this section. You can obtain details about CWE-615 at https://cwe.mitre.org/data/definitions/615.html.

6.12.3 Lack of Error Handling and Overly Verbose Error Handling

Improper error handling is a type of weakness and security malpractice that can provide information to an attacker to help him or her perform additional attacks on the targeted system. Error messages such as error codes, database dumps, and stack traces can provide valuable information to an attacker, such as information about potential flaws in the applications that could be further exploited.

A best practice is to handle error messages according to a well-thought-out scheme that provides a meaningful error message to the user, diagnostic information to developers and support staff, and no useful information to an attacker.
AlexV4_pose04.png

TIP OWASP provides detailed examples of improper error handling at https://owasp.org/www-community/Improper_Error_Handling. OWASP also provides a cheat sheet that discusses how to find and prevent error handling vulnerabilities; see https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html.

6.12.4 Practice - Insecure Code

This is a multiple choice question. Once you have selected an option, select the submit button below

You are testing the security of a digital store front application by attempting to force the application to crash. Why is this activity included in a penetration test?
to see if developers included informative comments with detailed information in the application source code
to determine if an attacker can exploit security vulnerabilities when a system or an application attempts to perform two or more operations simultaneously with proper sequence
to see if the application provides error codes, database dumps, or stack traces that could provide valuable information to help attackers perform additional attacks
to determine if usernames and passwords are specified in a web application

6.12.5 Hard-Coded Credentials

Hard-coded credentials are catastrophic flaws that an attacker can leverage to completely compromise an application or the underlying system. MITRE covers this malpractice (or weakness) in CWE-798. You can obtain detailed information about CWE-798 at https://cwe.mitre.org/data/definitions/798.html.

6.12.6 Race Conditions

A race condition occurs when a system or an application attempts to perform two or more operations at the same time. However, due to the nature of such a system or application, the operations must be done in the proper sequence in order to be done correctly. When an attacker exploits such a vulnerability, he or she has a small window of time between when a security control takes effect and when the attack is performed. The attack complexity in race conditions is very high. In other words, race conditions are very difficult to exploit.

NOTE Race conditions are also referred to as time of check to time of use (TOCTOU) attacks.

An example of a race condition is a security management system pushing a configuration to a security device (such as a firewall or an intrusion prevention system) such that the process rebuilds access control lists and rules from the system. An attacker may have a very small time window in which it could bypass those security controls until they take effect on the managed device.


6.12.7 Unprotected APIs

Application programming interfaces (APIs) are used everywhere today. A large number of modern applications use APIs to allow other systems to interact with the application. Unfortunately, many APIs lack adequate controls and are difficult to monitor. The breadth and complexity of APIs also make it difficult to automate effective security testing. There are a few methods or technologies behind modern APIs:

    Simple Object Access Protocol (SOAP): This standards-based web services access protocol was originally developed by Microsoft and has been used by numerous legacy applications for many years. SOAP exclusively uses XML to provide API services. XML-based specifications are governed by XML Schema Definition (XSD) documents. SOAP was originally created to replace older solutions such as the Distributed Component Object Model (DCOM) and Common Object Request Broker Architecture (CORBA). You can find the latest SOAP specifications at https://www.w3.org/TR/soap.
    Representational State Transfer (REST): This API standard is easier to use than SOAP. It uses JSON instead of XML, and it uses standards such as Swagger and the OpenAPI Specification ( https://www.openapis.org ) for ease of documentation and to encourage adoption.
    GraphQL: GraphQL is a query language for APIs that provides many developer tools. GraphQL is now used for many mobile applications and online dashboards. Many different languages support GraphQL. You can learn more about GraphQL at https://graphql.org/code.

NOTE SOAP and REST use the HTTP protocol. However, SOAP is limited to a more strict set of API messaging patterns than REST. As a best practice, you should always use Hypertext Transfer Protocol Secure (HTTPS), which is the secure version of HTTP. HTTPS uses encryption over the Transport Layer Security (TLS) protocol in order to protect sensitive data.

An API often provides a roadmap that describes the underlying implementation of an application. This roadmap can give penetration testers valuable clues about attack vectors they might otherwise overlook. API documentation can provide a great level of detail that can be very valuable to a penetration tester. API documentation can include the following:

    Swagger (OpenAPI): Swagger is a modern framework of API documentation and development that is the basis of the OpenAPI Specification (OAS). Additional information about Swagger can be obtained at https://swagger.io. The OAS specification is available at https://github.com/OAI/OpenAPI-Specification.
    Web Services Description Language (WSDL) documents: WSDL is an XML-based language that is used to document the functionality of a web service. The WSDL specification can be accessed at https://www.w3.org/TR/wsdl20-primer.
    Web Application Description Language (WADL) documents: WADL is an XML-based language for describing web applications. The WADL specification can be obtained from https://www.w3.org/Submission/wadl.

When performing pen testing against an API, it is important to collect full requests by using a proxy such as Burp Suite or OWASP ZAP. (You will learn more about these tools in Module 10.) It is important to make sure that the proxy is able to collect full API requests and not just URLs because REST, SOAP, and other API services use more than just GET parameters.

When you are analyzing the collected requests, look for nonstandard parameters and for abnormal HTTP headers. You should also determine whether a URL segment has a repeating pattern across other URLs. These patterns can include a number or an ID, dates, and other valuable information. Inspect the results and look for structured parameter values in JSON, XML, or even nonstandard structures.
AlexV4_pose04.png

TIP If you notice that a URL segment has many values, it may be because it is a parameter and not a folder or a directory on the web server. For example, if the URL http://web.h4cker.org/s/abcd/page repeats with different values for abcd (such as http://web.h4cker.org/s/dead/page or http://web.h4cker.org/s/beef/page), those changing values are definitely API parameters.

You can also use fuzzing to find API vulnerabilities (or vulnerabilities in any application or system). According to OWASP, “Fuzz testing or Fuzzing is an unknown environment/black box software testing technique, which basically consists in finding implementation bugs using malformed/semi-malformed data injection in an automated fashion.”

NOTE Refer to the OWASP page https://www.owasp.org/index.php/Fuzzing to learn about the different types of fuzzing techniques to use with protocols, applications, and other systems. In Module 10 you will see examples of fuzzers and how to use them to find vulnerabilities.

When testing APIs, you should always analyze the collected requests to optimize fuzzing. After you find potential parameters to fuzz, determine the valid and invalid values that you want to send to the application. Of course, fuzzing should focus on invalid values (for example, sending a GET or PUT with large values or special characters, Unicode, and so on). In Module 10 you will learn about tools like Radamsa (https://gitlab.com/akihe/radamsa) that can be used to create fuzzing parameters for testing applications, protocols, and more.

NOTE OWASP has a REST Security Cheat Sheet that provides numerous best practices on how to secure RESTful (REST) APIs. See https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html.

The following are several general best practices and recommendations for securing APIs:

    Secure API services to provide HTTPS endpoints with only a strong version of TLS.
    Validate parameters in the application and sanitize incoming data from API clients.
    Explicitly scan for common attack signatures; injection attacks often betray themselves by following common patterns.
    Use strong authentication and authorization standards.
    Use reputable and standard libraries to create the APIs.
    Segment API implementation and API security into distinct tiers; doing so frees up the API developer to focus completely on the application domain.
    Identify what data should be publicly available and what information is sensitive.
    If possible, have a security expert do the API code verification.
    Make internal API documentation mandatory.
    Avoid discussing company API development (or any other application development) on public forums.

NOTE CWE-227, “API Abuse,” covers unsecured APIs. For detailed information about CWE-227, see https://cwe.mitre.org/data/definitions/227.html.

6.12.8 Practice - Unprotected APIs

This question component requires you to select the matching option. When you have selected your answers select the submit button.

Match the technologies behind modern APIs to their descriptions.

6.12.9 Hidden Elements

Web application parameter tampering attacks can be executed by manipulating parameters exchanged between the web client and the web server in order to modify application data. This could be achieved by manipulating cookies (as discussed earlier in this module) and by abusing hidden form fields.

It might be possible to tamper with the values stored by a web application in hidden form fields. Let’s take a look at an example of a hidden HTML form field. Suppose that the following is part of an e-commerce site selling merchandise to online customers:

<input type="hidden" id="123" name="price" value="100.00">

In the hidden field shown in this example, an attacker could potentially edit the value information to reduce the price of an item. Not all hidden fields are bad; in some cases, they are useful for the application, and they can even be used to protect against CSRF attacks.

6.12.10 Lack of Code Signing

Code signing (or image signing) involves adding a digital signature to software and applications to verify that the application, operating system, or any software has not been modified since it was signed. Many applications are still not digitally signed today, which means attackers can easily modify and potentially impersonate legitimate applications.

Code signing is similar to the process used for SSL/TLS certificates. A key pair (one public key and one private key) identifies and authenticates the software engineer (developer) and his or her code. This is done by employing trusted certificate authorities (CAs). Developers sign their applications and libraries using their private key. If the software or library is modified after signing, the public key in a system will not be able to verify the authenticity of the developer’s private key signature.

Subresource Integrity (SRI) is a security feature that allows you to provide a hash of a file fetch by a web browser (client). SRI verifies file integrity and ensures that files are delivered without any tampering or manipulation by an attacker.

6.12.11 Additional Web Application Hacking Tools

Many ethical and malicious hackers use web proxies to exploit vulnerabilities in web applications. A web proxy, in this context, is a piece of software that is typically installed in the attacker’s system to intercept, modify, or delete transactions between a web browser and a web application. Figure 6-24 shows how a web proxy works.

Figure 6-24 - How a Web Proxy Works

Two of the most popular web proxies used to hack web applications are Burp Suite and ZAP. Burp Suite is a collection of tools and capabilities, one of which is a web proxy.

Burp Suite, also simply known as “Burp,” comes in two different versions: the free Burp Suite Community Edition and the paid Burp Suite Professional Edition. Figure 6-25 shows the Burp Suite Community Edition being used to intercept transactions from the attacker’s web browser and a web application. You can see how session cookies and other information can be intercepted and captured in the proxy.


TIP Burp Suite was created by a company called PortSwigger, which has a very comprehensive (and free) web application security online course at https://portswigger.net/web-security. This course provides free labs and other materials that can help you prepare for the PenTest+ and other certifications.

OWASP ZAP is a collection of tools including proxy, automated scanning, fuzzing, and other capabilities that can be used to find vulnerabilities in web applications. You can download OWASP ZAP, which is free, from https://www.zaproxy.org. Figure 6-26 shows how OWASP ZAP is used to perform an automated scan of a vulnerable web application. In this example, OWASP ZAP found two vulnerable JavaScript libraries that an attacker could leverage to compromise the web application.

Earlier in this module, you learned about the tool DirBuster, which can be used to perform active reconnaissance of a web application. There are other, more modern tools available to perform similar reconnaissance (including enumerating files and directories). The following are some of the most popular of them:

    gobuster: This tool, which is similar to DirBuster, is written in Go. You can download gobuster from https://github.com/OJ/gobuster.
    ffuf: This very fast web fuzzer is also written in Go. You can download ffuf from https://github.com/ffuf/ffuf.
    feroxbuster: This web application reconnaissance fuzzer is written in Rust. You can download feroxbuster from https://github.com/epi052/feroxbuster.

All of these tools use wordlists – that is, files containing numerous words that are used to enumerate files and, directories and crack passwords. Figure 6-27 shows how gobuster is able to enumerate different directories in a web application running on port 8888 on a system with the IP address 192.168.88.225. The attacker in this case is using a wordlist called mywordlist.

Figure 6-27 - Using gobuster to Enumerate Directories in a Web Application

6.12.12 Practice - Web Hacking Tools
This is a multiple choice question. Once you have selected an option, select the submit button below

You are looking for tools to use in a penetration test of a customer's web application. You want the software to intercept and forward all traffic between your testing VM and the customer's web site so you can examine and analyze all of the messages that are exchanged. Which tools should you consider? (Choose all that apply.)
Gobuster
Feroxbuster
DirBuster
Burp Suite
OWASP ZAP
Incomplete 6.12.13 Lab - Use the OWASP Web Security Testing Guide
6.12.13 Lab - Use the OWASP Web Security Testing Guide
AlexV4_pose03.png

Protego Security Solutions Task

There are many organizations that are dedicated to improving cybersecurity. They offer fantastic resources that are really helpful to us here at Protego. OWASP offers many resources and tools that are really awesome. They focus on web application security, so when you do application testing, you will find yourself turning to their resources often.

The OWASP WSTG is an amazing guide to testing for a really wide range of web application vulnerabilities, and offers concrete recommendations for threat mitigation. It is indispensable for making recommendations regarding vulnerabilities that we have discovered in our testing.

You should be familiar with it, so I want you to explore the WSTG website. After you check that out, we will do a brief vulnerability scan using the OWASP ZAP tool so you can see how it can work together with WSTG.

In this lab, you will complete the following objectives:

    Part 1: Investigate the WSTG
    Part 2: Scan a Website and Investigate Vulnerability References

Please answer the following questions after you have completed the lab.
Incomplete Skills Check
Skills Check
This is a multiple choice question. Once you have selected an option, select the submit button below

In the lab, you scanned a target for application vulnerabilities using OWASP ZAP. You explored one of the vulnerabilities that you discovered. What type of vulnerability was it and what was its cause? (Choose all that apply.)
an out-of-date software version
remote code execution
SQL injection
directory traversal
security misconfiguration
insufficient input validation
Incomplete Lab Survey
Lab Survey
Matching. Select from lists and then submit.

Please tell me about your experience with the lab by indicating your level of agreement with the following statements.
I feel confident about the skills I practiced with this lab.
Completing this lab was a good use of my time.
 
