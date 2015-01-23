jboss-websocket-hello-ssl: A simple WebSocket application
========================
Author: Sande Gilda, Emmanuel Hugonett, Claudianus Adjai   
Level: Beginner  
Technologies: WebSocket, CDI, JSF  
Summary: The `websocket-hello` quickstart demonstrates how to create a simple WebSocket application.  
Target Product: JBoss EAP  
Source: <https://github.com/jboss-developer/jboss-eap-quickstarts>  

What is it?
-----------

The `websocket-hello-ssl` quickstart demonstrates how to create a simple WebSocket-enabled application in Red Hat JBoss Enterprise Application Platform with 2 way SSL enabled. It consists of the following:

* A JavaScript enabled WebSocket HTML client.
* A WebSocket server endpoint that uses annotations to interact with the WebSocket events.
* A `jboss-web.xml` file configured to enable WebSockets

_Note: This quickstart demonstrates only a few of the basic functions. A fully functional application should provide better error handling and intercept and handle additional events._

System requirements
-------------------

The application this project produces is designed to be run on Red Hat JBoss Enterprise Application Platform 6.3 or later, which is running on Java 7 or later.

All you need to build this project is Java 6 (Java SDK 1.6) or later, Maven 3.0 or later. 

 
Configure Maven
---------------

If you have not yet done so, you must [Configure Maven](https://github.com/jboss-developer/jboss-developer-shared-resources/blob/master/guides/CONFIGURE_MAVEN.md#configure-maven-to-build-and-deploy-the-quickstarts) before testing the quickstarts.


Configure the JBoss EAP Server
---------------------------

As a reminder, this application requires JBoss EAP 6.3 or later, running on Java 7 or later.

Before you begin, you must enable the `NIO2` connector in the `web` subsystem of the JBoss EAP server configuration file. 

1. Before you begin, back up your server configuration file
    * If it is running, stop the JBoss EAP server.
    * Backup the file: `EAP_HOME/standalone/configuration/standalone.xml`
    * After you have completed testing this quickstart, you can replace this file to restore the server to its original configuration.
2. Review the create-ca-ks-ts-usrcert-usingkeytool.sh script in the root of this quickstart. The file is used to create a set of PKI based certificate and root authority to be used for the 2 way ssl authentication. Make any changes you need like name of the CA, password to use and username ...
   *There is not bat equivalent at the moment but you should be able to copy and paste  each of the command in the command window to achieve the same result. 
   
3. Run the above script under the configuration directory of the EAP_HOME so that the certificates are placed under the sub-directory provided in the script above. 

4. Import the user certificates and root authority certificate into your browser where you intend to test the application from.

5. Start the JBoss EAP server by typing the following: 

        For Linux:  EAP_HOME/bin/standalone.sh
        For Windows:  EAP_HOME\bin\standalone.bat
6. Review the `configure-https-connector.cli` file in the root of this quickstart directory. This script configures the https connector in the `web` subsystem to use the "NIO2" protocol as well as adds a security domain for pki based authentication.

7. Open a new command prompt, navigate to the root directory of this quickstart, and run the following command, replacing EAP_HOME with the path to your server:

        For Linux: EAP_HOME/bin/jboss-cli.sh --connect --file=configure-https-connector.cli 
        For Windows: EAP_HOME\bin\jboss-cli.bat --connect --file=configure-https-connector.cli
You should see the following result when you run the script:

        The batch executed successfully.
        {"outcome" => "success"}
8. Stop the JBoss EAP server.

Review the Modified Server Configuration
-----------------------------------

After stopping the server, open the `EAP_HOME/standalone/configuration/standalone.xml` file and review the changes. 

The  `http` connector in the `web` subsystem was modified to use the "org.apache.coyote.http11.Http11NioProtocol" protocol:

        <subsystem xmlns="urn:jboss:domain:web:2.2" default-virtual-server="default-host" native="false">
            <connector name="http" protocol="org.apache.coyote.http11.Http11NioProtocol" scheme="http" socket-binding="http"/>
            <virtual-server name="default-host" enable-welcome-root="true">
            <alias name="localhost"/>
                <alias name="example.com"/>
            </virtual-server>
        </subsystem>


Start the JBoss EAP Server
-------------------------

1. Open a command prompt and navigate to the root of the JBoss EAP directory.
2. The following shows the command line to start the server:

        For Linux:   EAP_HOME/bin/standalone.sh
        For Windows: EAP_HOME\bin\standalone.bat

 
Build and Deploy the Quickstart
-------------------------

_NOTE: The following build command assumes you have configured your Maven user settings. If you have not, you must include Maven setting arguments on the command line. See [Build and Deploy the Quickstarts](../README.md#build-and-deploy-the-quickstarts) for complete instructions and additional options._

1. Make sure you have started the JBoss EAP server as described above.
2. Open a command prompt and navigate to the root directory of this quickstart.
3. Type this command to build and deploy the archive:

        mvn clean install jboss-as:deploy

4. This will deploy `target/jboss-websocket-hello.war` to the running instance of the server.

_Note: If JBoss EAP is running on Java 6, you will see the following message in the server log when you deploy a websocket enabled application. This is a reminder that it needs to be running on Java 7 or greater._

        INFO [org.apache.tomcat.websocket] (ServerService Thread Pool -- 64) JBWEB008813: WebSocket support is not available when running on Java 6

Access the application 
---------------------

The application will be running at the following URL: <https://localhost:8443/jboss-websocket-hello-ssl>. 

1. Click on the `Open Connection` button to create the WebSocket connection and display current status of `Open`.
2. Type a name and click `Say Hello` to create and send the 'Say hello to `<NAME>`' message. The message appears in the server log and a response is sent to the client.
3. Click on the `Close Connection` button to close the WebSocket connection and display the current status of `Closed`.
4. If you attempt to send another message after closing the connection, the following message appears on the page: "WebSocket connection is not established. Please click the Open Connection button".


Undeploy the Archive
--------------------

1. Make sure you have started the JBoss EAP server as described above.
2. Open a command prompt and navigate to the root directory of this quickstart.
3. When you are finished testing, type this command to undeploy the archive:

        mvn jboss-as:undeploy


Remove the NIO2  HTTP Connector Configuration
----------------------------

You can remove the connector configuration by running the  `remove-https-connector.cli` script provided in the root directory of this quickstart or by manually restoring the back-up copy the configuration file. 

### Remove the Connector Configuration by Running the JBoss CLI Script

1. Start the JBoss EAP server by typing the following: 

        For Linux:  EAP_HOME/bin/standalone.sh
        For Windows:  EAP_HOME\bin\standalone.bat
2. Open a new command prompt, navigate to the root directory of this quickstart, and run the following command, replacing EAP_HOME with the path to your server:

        For Linux: EAP_HOME/bin/jboss-cli.sh --connect --file=remove-https-connector.cli
        For Windows: EAP_HOME\bin\jboss-cli.bat --connect --file=remove-https-connector-cli
This script restores the http connector protocol in the web subsystem of the server configuration file to the original `HTTP/1.1` protocol. You should see the following result when you run the script:

        The batch executed successfully.
        {"outcome" => "success"}


### Remove the Connector Configuration Manually
1. If it is running, stop the JBoss EAP server.
2. Replace the `EAP_HOME/standalone/configuration/standalone.xml` file with the back-up copy of the file.


Run the Quickstart in JBoss Developer Studio or Eclipse
-------------------------------------
You can also start the server and deploy the quickstarts or run the Arquillian tests from Eclipse using JBoss tools. For more information, see [Use JBoss Developer Studio or Eclipse to Run the Quickstarts](https://github.com/jboss-developer/jboss-developer-shared-resources/blob/master/guides/USE_JBDS.md#use-jboss-developer-studio-or-eclipse-to-run-the-quickstarts) 


_NOTE:_ Be sure to enable the `NIO2` connector in the `web` subsystem by running the JBoss CLI commands as described in the section above entitled *Configure the JBoss EAP Server*. Stop the server at the end of that step.


Debug the Application
------------------------------------

If you want to debug the source code of any library in the project, run the following command to pull the source into your local repository. The IDE should then detect it.

        mvn dependency:sources

  
