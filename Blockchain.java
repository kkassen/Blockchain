/*--------------------------------------------------------

1. Kyle Arick Kassen / Date: July 3, 2021 - July 12, 2021

2. Java version:

C:\Users\IQ1006\JavaPrograms\CSC435\Blockchain>java -version
openjdk version "11.0.4" 2019-07-16 LTS
OpenJDK Runtime Environment Corretto-11.0.4.11.1 (build 11.0.4+11-LTS)
OpenJDK 64-Bit Server VM Corretto-11.0.4.11.1 (build 11.0.4+11-LTS, mixed mode)

3. Compiling:
 • As per the assignment requirements—issue the following command twice:
    >javac -cp "gson-2.8.2.jar" Blockchain.java
    >javac -cp "gson-2.8.2.jar" Blockchain.java

4. Instructions and Details for Running the Program:
• Once complied [see above: #3]—
• Type the .bat file into the terminal command window:
>AllStart.bat
    • The .bat file contains the following:
        start java -cp ".;gson-2.8.2.jar" Blockchain 0
        start java -cp ".;gson-2.8.2.jar" Blockchain 1
        java -cp ".;gson-2.8.2.jar" Blockchain 2
*NOTE: running a single process will cause errors, batch file (as described above) should be used.
*NOTE: the .bat file should be included in the appropriate directory.

5. List of files needed for running the program:
[1] Blockchain.java
[2] .bat file (with appropriate commands--see above).

6. Notes:

Citations/Reference:
    [1] BlockInputG.java starter program written by Professor Clark Elliott using the below web sources.
    [2] BlackJ.java starter program written by Professor Clark Elliott using the below web sources.
    [3] bc.java starter program written by Professor Clark Elliott using the below web sources.
    [4] WorkB.java starter program written by Professor Clark Elliott using the below web sources.
Web Sources:
    http://www.fredosaurus.com/notes-java/data/strings/96string_examples/example_stringToArray.html
    https://beginnersbook.com/2013/12/linkedlist-in-java-with-example/
    https://www.javacodegeeks.com/2013/07/java-priority-queue-priorityqueue-example.html
    https://mkyong.com/java/how-to-parse-json-with-gson/
    http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
    https://www.mkyong.com/java/java-digital-signatures-example/
    https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
    https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
    https://www.mkyong.com/java/java-sha-hashing-example/
    https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
    https://www.java67.com/2014/10/how-to-pad-numbers-with-leading-zeroes-in-Java-example.html
    https://www.quickprogrammingtips.com/java/how-to-generate-sha256-hash-in-java.html  @
    https://dzone.com/articles/generate-random-alpha-numeric
    http://www.javacodex.com/Concurrency/PriorityBlockingQueue-Example

----------------------------------------------------------*/
//import statements: used to retrieve specified libraries/packages
//combined all import statements from the starter files provided by Professor Elliot. see header notes for references.
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.*;
import java.security.MessageDigest;
import java.security.*;
import java.util.Date;
import java.util.Random;
import java.util.UUID;
import java.util.Base64;
import java.util.Arrays;
import java.util.*;
import java.util.concurrent.*;
import java.util.Scanner;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.FileReader;
import java.io.Reader;
import java.io.StringWriter;
import java.io.StringReader;
import java.io.*;
import java.text.*;
import java.net.*;
import javax.crypto.Cipher;

public class Blockchain {
    //class level variables
    //empahsis on private, especially for the private key as we discussed the potential troubles associated with signatures
    static private PrivateKey privateKey;
    // this variable refers to the current input.txt file being read-in
    private static String FILENAME;
    //our alpha-numeric string for generating seeds during 'the work'
    private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    //as per assignment requirements serverName=localhost
    public static String serverName = "localhost";
    //this variable is used to reference the rsa algo in the keyPair method
    public static final String ALGORITHM = "RSA";
    static int NUMPROCESSES = 3;
    //this variable is used for holding the process id
    public static int PID;
    //this list is for holding our chain
    public static LinkedList<BlockRecord> BLOCKCHAIN = new LinkedList<>();
    //this list is for hold our unverified blocks
    public static LinkedList<BlockRecord> RECORDLIST = new LinkedList<>();
    //this list is for holding the publicKey-pid values
    public static List<keyFactory> KEYLIST = new ArrayList<>();


    //this is entirely based on Professor Elliott's provided bc starter file.
    //a method used in our priority queue to prioritize by timestamp
    public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>(){
        @Override
        public int compare(BlockRecord b1, BlockRecord b2){
            String s1 = b1.getTimeStamp();
            String s2 = b2.getTimeStamp();
            if (s1 == s2) {return 0;}
            if (s1 == null) {return -1;}
            if (s2 == null) {return 1;}
            return s1.compareTo(s2);
        }
    };
    //our priority queue. A major help in 'the work' portion of the program.
    static Queue<BlockRecord> ourPriorityQueue = new PriorityQueue<>(100, BlockTSComparator);


    //a method for reading the .txt files, 'building the unverified blocks', and storing the unverified blocks.
    //A modification of Professor Elliott's BlockInputG starter file
    public static LinkedList<BlockRecord> readTxt(int pnum) {
        //a switch statement for identifying process id and associated input.txt file for reading
        switch (pnum) {
            case 1: FILENAME = "BlockInput1.txt";break;
            case 2: FILENAME = "BlockInput2.txt";break;
            default: FILENAME = "BlockInput0.txt"; break;
        }

        try {
            //for retrieving text from the input.txt file
            BufferedReader br = new BufferedReader(new FileReader(FILENAME));
            //a structure for building our block; field-by-field
            String[] tokens = new String[10];
            //a variable used to store input rext from the buffer
            String InputLineStr;
            //the variables for holding the block fields (block-id and uuid)
            String suuid;
            UUID idA;
            //reading text from the buffer and storing it in the local variable InputLineStr
            while ((InputLineStr = br.readLine()) != null) {
                //creating a new Blockrecord object for populating our block fields
                BlockRecord BR = new BlockRecord();
                // creating a slight delay for time variations in the timestamp field of the block
                try{Thread.sleep(1001);}catch(InterruptedException e){}
                //creating the timestamp value for the block
                Date date = new Date();
                String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
                String TimeStampString = T1 + "." + pnum;

                //assigning values to the variables for the block fields (block-id and uuid)
                suuid = new String(UUID.randomUUID().toString());
                idA = UUID.randomUUID();

                //signing the block. [from Professor Elliott's blockj starter file]
                KeyPair keyPair = generateKeyPair(999);
                byte[] digitalSignature = signData(suuid.getBytes(), keyPair.getPrivate());
                String eSignature = Base64.getEncoder().encodeToString(digitalSignature);

                //populating the values for the block fields using the setters created in the blockrecord class.
                BR.setBlockID(suuid);
                BR.setTimeStamp(TimeStampString);
                BR.setUUID(idA);
                BR.seteSignature(eSignature);
                BR.setVerificationProcessID(Integer.toString(Blockchain.PID));
                BR.setRandomSeed(Blockchain.randomAlphaNumeric(8));
                tokens = InputLineStr.split(" +");
                BR.setFname(tokens[0]);
                BR.setLname(tokens[1]);
                BR.setDOB(tokens[2]);
                BR.setSSNum(tokens[3]);
                BR.setDiag(tokens[4]);
                BR.setTreat(tokens[5]);
                BR.setRx(tokens[6]);
                //adding the unverified block to our unverified blocks list
                RECORDLIST.add(BR);
            }
        } catch (Exception e) {e.printStackTrace();}

        return RECORDLIST;
    }

    //this is entirely based on Professor Elliott's provided blockj starter file.
    //a simple method for producing [public key/private key] pairs
    public static KeyPair generateKeyPair(long seed) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);

        return (keyGenerator.generateKeyPair());
    }

    //this is entirely based on Professor Elliott's provided workb starter file.
    //a simple method for generating a random alph-numeric of string type. Handy for 'the work' portion of the program.
    public static String randomAlphaNumeric(int count) {
        StringBuilder builder = new StringBuilder();
        while (count-- != 0) {
            int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }

    //this is entirely based on Professor Elliott's provided blockj starter file.
    //this method is used to create esignature and since it involves signatures we use the private key
    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(data);
        return (signer.sign());
    }

    //this is largely based on code from Professor Elliott's provided blockj starter file.
    // a simple method for generating public and private keys and associated process id
    public static keyFactory makeKey(int pnum){
        keyFactory KF = new keyFactory(); // creating a new keyFactory type object
        try {
            Random rk = new Random(); // creating a new Random type object
            int rs = rk.nextInt(999); // retrieve a random int to use as the seed in the generateKeyPair method
            KeyPair keyPair = generateKeyPair(rs); //retrieves a pair of keys
            PublicKey publicKey = keyPair.getPublic(); // retrieves public key
            privateKey = keyPair.getPrivate(); //retrieves private key
            //base 64 encoding for public key
            String encodedPK = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            KF.setPnum(pnum); //associating with the appropriate process id by setting the value
            KF.setPublicKey(encodedPK); //associating with the appropriate public key by setting the value
        }catch (Exception x) {x.printStackTrace();}
        return KF;
    }

    //this is largely based on Professor Elliott's provided bc starter file.
    //a method used for sending/multicasting the public key and associated pid to all process id's
    public void KeySend (keyFactory KF){
        Socket sock; //Socket type representing a 'socket' mechanism
        PrintStream toServer; //variable for sending PrintStream type to the respective server
        try{
            //creating a gson object for translating java objects to json data
            Gson gson = new GsonBuilder().create();
            //converting java object [in this case, keyFactory type] to json data
            String json = gson.toJson(KF);
            //sending to each process id using a socket mechanism
            for(int i=0; i < NUMPROCESSES; i++){
                //a new Socket type Object which takes serverName and (serverbase + pid) [to get the incremented port number]
                sock = new Socket(serverName, Ports.KeyServerPortBase + (i));
                //for sending json data to the appropriate server
                toServer = new PrintStream(sock.getOutputStream());
                toServer.println(json); //sends json data via PrintStream type
                toServer.flush(); //cleaning/clearing the buffer
                sock.close(); //closing the socket mechanism
            }
        } catch (Exception x) {x.printStackTrace ();}
    }

    //this is largely based on Professor Elliott's provided bc starter file.
    //a method used for sending/multicasting the unverified block's to all process id's
    public void UnverifiedSend (BlockRecord b, int server){
        Socket UVBsock; //Socket type representing a 'socket' mechanism
        PrintStream toServerOOS; //variable for sending PrintStream type to the respective server
        try {
            //creating a gson object for translating java objects to json data
            Gson gson = new GsonBuilder().create();
            //converting java object [int this case, BlockRecord type] to json data
            String json = gson.toJson(b);
            //sending to each process id using a socket mechanism
            for (int i = 0; i < NUMPROCESSES; i++) {
                //a new Socket type Object which takes serverName and (serverbase + pid) [to get the incremented port number]
                UVBsock = new Socket(serverName, server + (i));
                //for sending json data to the appropriate server
                toServerOOS = new PrintStream(UVBsock.getOutputStream());
                toServerOOS.println(json); //sends json data via PrintStream type
                toServerOOS.flush(); //cleaning/clearing the buffer
            }
        }catch (Exception x) {x.printStackTrace ();}
    }

    //this is largely based on Professor Elliott's provided bc starter file.
    //a method used for sending/multicasting the blockchain to all process id's
    public static void winnerSend(LinkedList <BlockRecord> b, int server){
        Socket FSBsock; //Socket type representing a 'socket' mechanism
        PrintStream toServerOOS; //variable for sending PrintStream type to the respective server
        try {
            //creating a gson object for translating java objects to json data
            Gson gson = new GsonBuilder().create();
            //converting java object [int this case, BlockRecord type — LinkedList structure] to json data
            String json = gson.toJson(b);
            //sending to each process id using a socket mechanism
            for (int i = 0; i < NUMPROCESSES; i++) {
                //a new Socket type Object which takes serverName and (serverbase + pid) [to get the incremented port number]
                FSBsock = new Socket(serverName, server + (i));
                //for sending json data to the appropriate server
                toServerOOS = new PrintStream(FSBsock.getOutputStream());
                toServerOOS.println(json); //sends json data via PrintStream type
                toServerOOS.flush(); //cleaning/clearing the buffer
                FSBsock.close(); //closing the socket mechanism
            }
        }catch (Exception x) {x.printStackTrace ();}

    }

    public static void main(String args[]) {
        //the variables (block-id and uuid) for the genesis block
        String suuid;
        UUID idA;

        //retrieving the command line arguments and setting the process id value
        if (args.length < 1) PID = 0;
        else if (args[0].equals("0")) PID = 0;
        else if (args[0].equals("1")) PID = 1;
        else if (args[0].equals("2")) PID = 2;

        //setting the port values
        new Ports().setPorts();

        //letting process number two start the program (kind of...).  It will still run if you were to call process zero...
        //...or process one alone; however, there will be errors messages in the terminal windnow.
        if (PID != 0 || PID != 1 || PID ==2) {

            //creating a PublicKeyServer object and starting a new thread
            PublicKeyServer pks = new PublicKeyServer();
            new Thread (pks).start();
            //sleeping after thread creation/start to ensure process threads cooperate
            try { Thread.sleep(1001); } catch (InterruptedException e) {}

            //creating a UnverifiedBlockServer object and starting a new thread
            UnverifiedBlockServer ubs = new UnverifiedBlockServer();
            new Thread (ubs).start();
            //sleeping after thread creation/start to ensure process threads cooperate
            try { Thread.sleep(1001); } catch (InterruptedException e) {}

            //creating a BlockchainServer object and starting a new thread
            BlockchainServer bcs = new BlockchainServer();
            new Thread(bcs).start();
            //sleeping after thread creation/start to ensure process threads cooperate
            try { Thread.sleep(1001); } catch (InterruptedException e) {}

            //printing the below message on each process terminal window; announcing the process number specific to that...
            //...to that terminal window.
            System.out.println("\nHELLO FROM PROCESS: [" + PID + "]\n");
        }
            //creating 'block zero' or the 'genesis' block for addition to the blockchain
            try {
                //the time value for the genesis block
                Date date = new Date();
                String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
                String TimeStampString = T1 + "." + PID;

                //the block-id and uuid for the genesis block
                suuid = new String(UUID.randomUUID().toString());
                idA = UUID.randomUUID();

                //signing the gensis block. [from Professor Elliott's blockj starter file]
                KeyPair keyPair = generateKeyPair(999);
                byte [] digitalSignature = signData(suuid.getBytes(), keyPair.getPrivate());
                String eSignature = Base64.getEncoder().encodeToString(digitalSignature);

                BlockRecord genesis = new BlockRecord();
                //populating the values for the genesis block fields using the setters created in the blockrecord class.
                genesis.setBlockID(suuid);
                genesis.setTimeStamp(T1);
                genesis.setUUID(idA);
                genesis.seteSignature(eSignature);
                genesis.setVerificationProcessID("Genesis");
                genesis.setRandomSeed(Blockchain.randomAlphaNumeric(8));
                genesis.setFname("Alpha");
                genesis.setLname("alpha");
                genesis.setDOB("00-00-0000");
                genesis.setSSNum("000-00-0000");
                genesis.setDiag("zero");
                genesis.setTreat("00000000");
                genesis.setRx("more zeros please!");
                genesis.setChainPlacement(0);
                //adding the genesis block to the blockchain!
                BLOCKCHAIN.add(genesis);

            } catch (Exception e) {e.printStackTrace();}
            //calling the readTxt method to get the input from our text files.  Takes the current process id as an argument
            readTxt(PID);
            //calling the makeKey method to generate the public/private keys for the current process id
            //sleeping after method calls to ensure process threads cooperate
            try {Thread.sleep(1001);} catch (InterruptedException e) {}
            keyFactory keys = makeKey(PID);
            //calling the keySend method to multicast/send the keys to all processes
            Blockchain ks = new Blockchain();
            ks.KeySend(keys);
            //printing the keys for each process [on each process terminal windows]
            //sleeping after method calls to ensure process threads cooperate
            try {Thread.sleep(1001);} catch (InterruptedException e) {}
            for (int i=0; i<KEYLIST.size(); i++){
                System.out.println( "\nPUBLIC KEY FOR PROCESS: [" + KEYLIST.get(i).getPnum() + "]\n"
                        + KEYLIST.get(i).getPublicKey() +"\n");}
            //sleeping after method calls to ensure process threads cooperate
            try {Thread.sleep(1001);} catch (InterruptedException e) {}
            System.out.println("\nSENDING UNVERIFIED BLOCKS FROM PROCESS: [" + PID + "]\n");
            //printing the below message on each process terminal window; announcing that the unverified blocks have...
            //...been sent
            //sleeping after method calls to ensure process threads cooperate
            try {Thread.sleep(1001);} catch (InterruptedException e) {}
            //calling the unverifiedSend method for sending/multicasting (to all of the pid's) the unverified blocks...
            //...retrieved from each of the pid's text file input
            Blockchain uvs = new Blockchain();
            for (int j = 0; j < RECORDLIST.size(); j++) {
                uvs.UnverifiedSend(RECORDLIST.get(j), Ports.UnverifiedBlockServerPortBase);}
            //sleeping after method calls to ensure process threads cooperate
            try {Thread.sleep(1001);} catch (InterruptedException e) {}
            //creating a 'miner' object so we can start 'the work'
            Miner miner = new Miner();
            miner.start();
    }
}

//this is largely based on Professor Elliott's provided bc starter file.
class Ports {
    //assigning values to the base port variables
    public static int KeyServerPortBase = 4710;
    public static int UnverifiedBlockServerPortBase = 4820;
    public static int BlockchainServerPortBase = 4930;

    //declaring port variables
    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;

    //a set method for assinging/updating port values.  Super helpful for multicasting.
    public void setPorts(){
        //setting this up to align with assignment requirements: base + process id
        KeyServerPort = KeyServerPortBase + (Blockchain.PID); //{4710, 4711, 4712}
        UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + (Blockchain.PID); //{4820,4821,4822}
        BlockchainServerPort = BlockchainServerPortBase + (Blockchain.PID); //{4930,4931,4932}
    }
}

//this is largely based on Professor Elliott's provided BlockInputG starter file.
class BlockRecord {
    //theese variables are used for the 'fields' in each of the 'blocks'
    String BlockID;
    String TimeStamp;
    String VerificationProcessID;
    UUID uuid;
    String Fname;
    String Lname;
    String SSNum;
    String DOB;
    String RandomSeed;
    String Diag;
    String Treat;
    String Rx;
    String eSignature;
    int chainPlacement;

    //defining 'get' and 'set' methods to allow for retrieving, initializing, and updating block field information
    public String getBlockID() {return BlockID;}
    public void setBlockID(String BID){this.BlockID = BID;}

    public String getTimeStamp() {return TimeStamp;}
    public void setTimeStamp(String TS){this.TimeStamp = TS;}

    public String getVerificationProcessID() {return VerificationProcessID;}
    public void setVerificationProcessID(String VID){this.VerificationProcessID = VID;}

    public UUID getUUID() {return uuid;}
    public void setUUID (UUID ud){this.uuid = ud;}

    public String getLname() {return Lname;}
    public void setLname (String LN){this.Lname = LN;}

    public String getFname() {return Fname;}
    public void setFname (String FN){this.Fname = FN;}

    public String getSSNum() {return SSNum;}
    public void setSSNum (String SS){this.SSNum = SS;}

    public String getDOB() {return DOB;}
    public void setDOB (String RS){this.DOB = RS;}

    public String getDiag() {return Diag;}
    public void setDiag (String D){this.Diag = D;}

    public String getTreat() {return Treat;}
    public void setTreat (String Tr){this.Treat = Tr;}

    public String getRx() {return Rx;}
    public void setRx (String Rx){this.Rx = Rx;}

    public String getRandomSeed() {return RandomSeed;}
    public void setRandomSeed (String RS){this.RandomSeed = RS;}

    public String geteSignature() {return eSignature;}
    public void seteSignature(String ES) {this.eSignature = ES;}

    public int getChainPlacement(){return chainPlacement;}
    public void setChainPlacement(int CP){this.chainPlacement = CP;}

}

//this is largely based on Professor Elliott's provided bc starter file.
class PublicKeyWorker extends Thread {
    keyFactory KF = new keyFactory(); //creating a new keyFactory object
    Socket keySock; //Socket type representing a 'socket' mechanism.
    PublicKeyWorker (Socket s) {keySock = s;} //a 'setter' function which takes one argument of type Socket.
    public void run(){
        Gson gson = new Gson(); //creating a gson object for translating json data to java objects
        try{
            //for retrieving information sent to the publickeyserver
            BufferedReader in = new BufferedReader(new InputStreamReader(keySock.getInputStream()));
            String data = in.readLine (); //reading from the buffer
            //converting json data (read from the buffer) to a java object of keyFactory class
            KF = gson.fromJson(data,keyFactory.class);
            Blockchain.KEYLIST.add(KF); //storing the public key and associated process id
            keySock.close(); //closing the socket mechanism
        } catch (IOException x){x.printStackTrace();}
    }
}

class PublicKeyServer implements Runnable {
    public void run(){
        int q_len = 6; //int type variable representing a queue length of six.  related to the OS.
        Socket keySock; //Socket type representing a 'socket' mechanism.
        //printing opening message to each process terminal window; announcing that the PublicKeyServer is running
        //System.out.println("\n*****ATTENTION GRADER: NOT ALL CHECKLIST REQUIREMENTS WERE COMPLETED*****\n");
        System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
        try{
            //a new ServerSocket type Object which takes port number and int type arguments
            ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);
            while (true) {
                keySock = servsock.accept(); //for acceptance of socket connection
                new PublicKeyWorker (keySock).start(); //gernerates the PublicKeyWorker Thread which takes a Socket type
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

//this is largely based on Professor Elliott's provided bc starter file.
class UnverifiedBlockServer implements Runnable {
    public void run(){
        int q_len = 6; //int type variable representing a queue length of six.  related to the OS.
        Socket sock; //Socket type representing a 'socket' mechanism.
        //printing message to each process terminal window; announcing that the UnverifiedBlockServer is running
        System.out.println("\nStarting the Unverified Block Server input thread using " +
                Integer.toString(Ports.UnverifiedBlockServerPort));
        try {
            //a new ServerSocket type Object which takes port number and int type arguments
            ServerSocket UVBServer = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
            while (true) {
                //for acceptance of socket connection
                sock = UVBServer.accept();
                //gernerates the UnverifiedBlockWorker Thread which takes a Socket type
                new UnverifiedBlockWorker(sock).start();
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }

    class UnverifiedBlockWorker extends Thread {
        Socket sock; //Socket type representing a 'socket' mechanism.
        UnverifiedBlockWorker (Socket s) {sock = s;} //a 'setter' function which takes one argument of type Socket.
        public void run(){
            Gson gson = new Gson(); //creating a gson object for translating json data to java objects
            try{
                //for retrieving information sent to the unverifiedBlockServer
                BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
                String json = in.readLine(); //reading from the buffer
                //converting json data (read from the buffer) to a java object of BlockRecord type
                BlockRecord blockRecordData = gson.fromJson(json,BlockRecord.class);
                //checking to ensure that each PID had a full list of unverified blocks.
                System.out.println("recieved: " + blockRecordData.getFname()+ " " + blockRecordData.getLname()
                        + " from process: [" + blockRecordData.getVerificationProcessID() +"]");
                //adding the unverified blocks to our priority queue
                Blockchain.ourPriorityQueue.add(blockRecordData);
            } catch (Exception x){x.printStackTrace();}
        }
    }
}

//this is largely based on Professor Elliott's provided bc starter file.
class BlockchainWorker extends Thread {
    Socket sock; //Socket type representing a 'socket' mechanism.
    BlockchainWorker (Socket s) {sock = s;} //a 'setter' function which takes one argument of type Socket.
    public void run(){
        Gson gson = new Gson(); //creating a gson object for translating json data to java objects
        try{
            //for retrieving information sent to the BlockchainServer
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            String blockDataIn = in.readLine(); //reading from the buffer
            //converting json data (read from the buffer) to a java object of BlockRecord class (type=array).
            BlockRecord [] blockRecordData = gson.fromJson(blockDataIn,BlockRecord[].class);
            //create a gson object for writing the ledger to disk
            Gson gsonbuilder = new GsonBuilder().setPrettyPrinting().create();
            //creating a new FileWriter type object that will hold our output json ledger file
            try (FileWriter writer = new FileWriter("BlockchainLedger.json")) {
                //converting BlockRecord array back to json data and writing output to disk
                gsonbuilder.toJson(blockRecordData, writer);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (IOException x){x.printStackTrace();}
    }
}
class BlockchainServer implements Runnable {
    public void run(){
        int q_len = 6; //int type variable representing a queue length of six.  related to the OS.
        Socket sock; //Socket type representing a 'socket' mechanism.
        //printing message to each process terminal window; announcing that the BlockChainServer is running
        System.out.println("\nStarting the Blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort));
        try{
            //a new ServerSocket type Object which takes port number and int type arguments
            ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
            while (true) {
                //for acceptance of socket connection
                sock = servsock.accept();
                new BlockchainWorker (sock).start(); //gernerates the BlockChainWorker Thread which takes a Socket type
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

//A simple class that provide the 'get' and 'set' methods for the keys.
// Of course, they must be paired with the appropriate process id.
class keyFactory {
    String publicKey;
    int pnum;

    public int getPnum(){return this.pnum;}
    public void setPnum(int PN){ this.pnum = PN;}

    public String getPublicKey(){ return this.publicKey;}
    public void setPublicKey(String PK){this.publicKey = PK;}
}

//the miner class does 'the work', adds the winning blocks to the blockchain, and calls the multicast method 'winnerSend()'
//this is largely based on Professor Elliott's provided workb starter file.
class Miner extends Thread {
    //this little method is entirely based on Professor Elliott's provided blockj starter file.
    //it converts an array of bytes to a string.
    public static String ByteArrayToString(byte[] ba) {
        StringBuilder hex = new StringBuilder(ba.length * 2);
        for (int i = 0; i < ba.length; i++) {
            hex.append(String.format("%02X", ba[i]));
        }
        return hex.toString();
    }
    static String randString; //variable that holds the random alpha-numeric value
    public void run() {
        // variable for holding all the block field data that is concatenated with the random string
        String concatString = "";
        String stringOut = ""; //variable for holding the hash value
        try {
            //keeps count for the 'chain placement'. starts at one because '0' is reserved for the genesis block
            int n = 1;
            //printing message to terminal window of each process; announcing that the work is starting.
            System.out.println("\n<-----STARTING COMPUTATIONS (THE WORK BEGINS FOR PROCESS: ["
                    +Blockchain.PID+"])----->\n");
            while (true) {
                //for retrieving the block at the head of the priority queue; we use it for 'the work'.
                BlockRecord b = Blockchain.ourPriorityQueue.poll();
                //we can end 'the work' once the priority queue has no more blocks to process
                if (b == null) {
                    //printing message to terminal window of each process; announcing that the work has ended.
                    System.out.println("\n<-----COMPUTATIONS COMPLETE (THE WORK IS DONE FOR PROCESS: ["
                            +Blockchain.PID+"])----->\n");
                    break; //exit the outter while loop
                }
                //as mentioned in the instructions, building the 'block data' by concatenation
                String bData = b.getBlockID() + b.getDiag() + b.getDOB() + b.getFname() + b.getLname() + b.getDiag()
                        + b.getRx() + b.getSSNum() + b.getRandomSeed() + b.geteSignature() + b.getTimeStamp();

                //variable that holds the random alpha-numeric value. calls the helper method for generating the random...
                //...alpha-numeric value.
                randString = Blockchain.randomAlphaNumeric(8);

                //int type used for checking if our value is above or below the 20,000 threshold
                int workNumber = 0;
                //a simple flag for doing the work. while true = do the work.  It is set to false once the puzzle is solved...
                //...and we break out for the next Blockrecord in our priority queue.
                boolean flag = true;
                //and 'the work' begins!
                while (flag) {
                    //sleeping a little to slow the work
                    try { Thread.sleep(300);} catch (InterruptedException e) {}
                    //all the block field data is concatenated with the random string generated...
                    //...by calling the randomAlphaNumeric method.
                    randString = Blockchain.randomAlphaNumeric(8);
                    concatString = bData + randString;

                    //generates the hash value
                    MessageDigest MD = MessageDigest.getInstance("SHA-256");
                    byte[] bytesHash = MD.digest(concatString.getBytes("UTF-8"));

                    //use the helper method to convert from byte [] array to string
                    stringOut = ByteArrayToString(bytesHash);
                    //printing message to terminal window of each process; announcing the hash value.
                    System.out.println("HASH= " + stringOut);

                    //int type used for checking if our value is above or below the 20,000 threshold
                    workNumber = Integer.parseInt(stringOut.substring(0, 4), 16);

                    if (!(workNumber < 20000)) {
                        //printing message to terminal window of each process; announcing that more work is required.
                        System.out.format("%d > 20,000 [STATUS= NOT SOLVED]\n", workNumber);
                    }
                    if (workNumber < 20000) {
                        flag = false;
                        //printing message to terminal window of each process; announcing that the puzzle is solved.
                        System.out.format("%d < 20,000 [STATUS= SOLVED]\n", workNumber);
                        //updating the time stamp field which determines the winner and creates a competitive environment
                        Date date = new Date();
                        String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
                        String TimeStampString = T1 + "." + Blockchain.PID;
                        b.setTimeStamp(T1);
                        //adding the field 'chain placement' to each winning block...
                        //...which represents it's position in the blockchain.
                        //In other words, give the winning block it's place in the chain!
                        b.setChainPlacement(n);
                        Blockchain.BLOCKCHAIN.add(b); //add the winning block to the blockchain
                        // call the winnerSend method for sending/multicasting the updated blockchain to process id's
                        Blockchain.winnerSend(Blockchain.BLOCKCHAIN, Ports.BlockchainServerPortBase);
                        n++; //increment our variable for 'chain placement'
                        //printing message to terminal window of each process; announcing the winning process id and block position.
                        System.out.println("\n***BLOCK: [" + b.getChainPlacement() +
                                "] HAS BEEN ADDED TO THE CHAIN BY PROCESS: [" + b.getVerificationProcessID() +"]***\n");
                        break; //exit the inner while loop
                    }
                }
            }
        }catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}