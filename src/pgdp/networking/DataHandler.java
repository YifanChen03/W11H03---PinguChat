package pgdp.networking;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.json.JSONArray;
import org.json.JSONObject;

import javafx.application.Platform;
import pgdp.networking.DataHandler.ConnectionException;
import pgdp.networking.ViewController.Message;
import pgdp.networking.ViewController.User;

public class DataHandler {

    private DataInputStream in;
    private DataOutputStream out;
    private Socket socket;

    private Queue<Byte> handshakeMutex;
    private Thread inputHandler;

    private HttpClient client;
    private int id;
    private String username;
    private String password;
    
    public static String serverAddress = "carol.sse.cit.tum.de";
    
    private final static byte SUPPORTED_VERSION = 42;

    boolean connected;

    /**
     * Erstellt neuen HTTP Client für die Verbindung zum Server
     */
    public DataHandler() {
        handshakeMutex = new LinkedList<>();

        /************************
         * Your Code goes here: *
         ************************/
        client = HttpClient.newBuilder()
                .version(Version.HTTP_1_1)
                .followRedirects(Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(20))
                .build();
    }

/************************************************************************************************************************
 *                                                                                                                       *
 *                                       HTTP Handling                                                                   *
 *                                                                                                                       *
 *************************************************************************************************************************/

    /**
     * Registriert den Nutzer beim Server oder erfragt ein neues Passwort
     * Gibt bei Erfolg true zurück.
     * Endpoint: /api/user/register
     * @param username Nutzername
     * @param kennung TUM Kennung
     * @return Registrierung erfolgreich
     */
    public boolean register(String username, String kennung) {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://" + serverAddress + "/api/user/register"))
                .header("Content-Type", "application/json")
                .POST(BodyPublishers.ofString("{\"username\": \"" + username + "\",\"tum_kennung\": \"" + kennung + "\"}"))
                .build();

        HttpResponse<String> response = null;

        try {
            response = client.send(request, BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            return false;
        }

        // TODO: Zurückgeben, ob die Anfrage erfolgreich war.
        int statusCode = response.statusCode();
        return statusCode == 200;
    }

    /**
     * Hilfsmethode um nach erfolgreichem Login einen Authentifizierungstoken zu erhalten.
     * Returns null upon failure
     * @return Authentication token or null
     */
    public String requestToken() {

        if (this.username == null || this.password == null) {
            return null;
        }

        return requestToken(this.username, this.password);
    }

    /**
     * Erfragt Autentifizierungstoken vom Server.
     * Gibt null bei Fehler zurück
     * Endpoint: /token
     * @param username Nutzername
     * @param password Passwort
     * @return token oder null
     */
    private String requestToken(String username, String password) {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://" + serverAddress + "/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(BodyPublishers.ofString("username=" + username + "&password=" + password))
                .build();

        HttpResponse<String> response = null;

        try {
            response = client.send(request, BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            return null;
        }

        // TODO: Falls die Anfrage erfolgreich war, Token auslesen und zurückgeben.
        int statusCode = response.statusCode();

        if (statusCode == 200) {
            JSONObject responseAsJSONObject = new JSONObject(response.body());
            return responseAsJSONObject.getString("access_token");
        }

        return null;
    }

    /**
     * Initialer login.
     * Wenn ein Token mit Nutzername und Passwort erhalten wird, werden diese gespeichert.
     * Anschließend wird die Nutzer ID geladen.
     * Endpoint: /token
     *           /api/user/me
     * @param username Nutzername
     * @param password Passwort
     * @return Login erfolgreich
     */
    public boolean login(String username, String password) {
        // TODO: Token anfragen und, falls die Anfrage erfolgreich war, Nutzername und Passwort dieses DataHandlers setzen.
        String tempToken = requestToken(username, password);
        if (tempToken != null) {
            this.username = username;
            this.password = password;
        }

        //code that existed beforehand, changed "" to tempToken
        String token = tempToken;

        HttpRequest request = HttpRequest.newBuilder(URI.create("http://" + serverAddress + "/api/user/me/"))
                .header("accept", "application/json")
                .header("Authorization", "Bearer " + token)
                .GET()
                .build();

        HttpResponse<String> response = null;

        try {
            response = client.send(request, BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            return false;
        }

        // TODO: Zurückgeben, ob die Anfrage erfolgreich war und wenn ja, die ID dieses DataHandlers setzen.
        int statusCode = response.statusCode();
        if (statusCode == 200) {
            JSONObject responseAsJSONObject = new JSONObject(response.body());
            int id = responseAsJSONObject.getInt("id");
            this.id = id;
            return true;
        }

        return false;
    }

    /**
     * Erfragt alle öffentlichen Nutzer vom Server
     * Endpoint: /api/users
     * @return Map von Nutzern und IDs
     */
    public Map<Integer, User> getContacts() {

        HttpRequest request = HttpRequest.newBuilder(URI.create("http://" + serverAddress + "/api/users"))
                .header("Authorization", "Bearer " + requestToken(username, password))
                .GET()
                .build();

        HttpResponse<String> response = null;

        try {
            response = client.send(request, BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            return null;
        }

        // TODO: Erzeuge und fülle eine Map entsprechend der vom Server erhaltenen Antwort,
        //  falls die Anfrage erfolgreich war.
        int statusCode = response.statusCode();

        if (statusCode == 200) {
            JSONArray responseAsJSONArray = new JSONArray(response.body());

            Map<Integer, User> output = IntStream.range(0, responseAsJSONArray.length())
                    .mapToObj(index -> responseAsJSONArray.getJSONObject(index))
                    .collect(Collectors.toMap(jsonObject -> jsonObject.getInt("id"),
                            jsonObject -> new User(jsonObject.getInt("id"),
                                    jsonObject.getString("username"), new ArrayList<>())));

            /*for (int i = 0; i < responseAsJSONArray.length(); i++) {
                JSONObject tempJSONObject = responseAsJSONArray.getJSONObject(i);
                int id = tempJSONObject.getInt("id");
                String username = tempJSONObject.getString("username");
                output.put(id, new User(id, username, new ArrayList<>()));
            }*/

            return output;
        }

        return null;
    }

    /**
     * Erfragt alle Nachrichten, welche mit einem gewissen Nutzer ausgetauscht wurden.
     * Endpoint: /api/messages/with/
     * @param id ID des Partners
     * @param count Anzahl der zu ladenden Nachrichten
     * @param page Falls count gesetzt, gibt die Seite an Nachrichten an.
     * @return Liste der Abgefragten Nachrichten.
     */
    public List<Message> getMessagesWithUser(int id, int count, int page) {
        HttpRequest request = HttpRequest
                .newBuilder(URI.create("http://" + serverAddress + "/api/messages/with/"
                        + Long.toString(id)
                        + "?count=" + Integer.toString(count)
                        + "&count=" + Integer.toString(page)))
                .header("Authorization", "Bearer " + requestToken(username, password))
                .GET()
                .build();

        HttpResponse<String> response = null;

        try {
            response = client.send(request, BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            return null;
        }

        // TODO: Erzeuge und fülle eine List entsprechend der vom Server erhaltenen Antwort,
        //  falls die Anfrage erfolgreich war.
        int statusCode = response.statusCode();

        if (statusCode == 200) {
            JSONArray responseAsJSONArray = new JSONArray(response.body());

            List<Message> output = IntStream.range(0, responseAsJSONArray.length())
                    .mapToObj(index -> {
                        JSONObject tempJSONObject = responseAsJSONArray.getJSONObject(index);
                        LocalDateTime time = LocalDateTime.parse(tempJSONObject.getString("time"));
                        String text = tempJSONObject.getString("text");
                        int from_id = tempJSONObject.getInt("from_id");
                        Boolean self = from_id == this.id;
                        int message_id = tempJSONObject.getInt("id");
                        Message tempMessage = new Message(time, text, self, message_id);
                        return tempMessage;
                    })
                    .collect(Collectors.toList());

            return output;
        }

        return null;
    }

    /*-**********************************************************************************************************************
    *                                                                                                                       *
    *                                       Socket Handling                                                                 *
    *                                                                                                                       *
    *************************************************************************************************************************/

    /**
     * Thread Methode um ankommende Nachrichten zu behandeln
     */
    private void handleInput() {

        System.out.println("Input Handler started");

        try {
            while (true) {

                byte type = in.readByte();
                System.out.println("Recieved Message");

                switch (type) {
                    case 0 -> {
                        byte hsType = in.readByte();
                        if (hsType == 5) {

                            passHandshakeMessage(new byte[] {type, hsType});
                        }
                    }
                    case 1 -> {

                        int length = (in.readByte()<<8) | in.readByte();

                        byte[] content = new byte[length];
                        in.read(content);

                        displayMessage(new String(content, StandardCharsets.UTF_8));
                    }
                }
            }
        } catch (Throwable t) {
            t.printStackTrace();
            System.exit(-1);
        }
    }

    /**
     * Erstelle einen Socket und Verbinde mit dem Server.
     * Gebe Nutzer ID und Token an. Verifiziert Server Antworten
     * @throws ConnectionException
     */
    private void connect() throws ConnectionException {
        try {
            // TODO: Socket erstellen und bei Erfolg den Handshake mit dem Server ausführen.
            //  Der 'DataInputStream in' und 'DataOutputStream out' sollen entsprechend zum Lesen/Schreiben
            //  des Input-/Output-Streams des Sockets gesetzt werden.
            Socket tempSocket = new Socket(serverAddress, 1337);
            DataInputStream tempDIS;
            DataOutputStream tempDOS;
            byte[] bytes;

            //check Server Hello
            tempDIS = (DataInputStream) tempSocket.getInputStream();
            bytes = tempDIS.readAllBytes();

            if (bytes[0] != 0 || bytes[1] != 0 || bytes[2] != 42) {
                throw new ConnectionException();
            }

            //send Client Hello
            bytes = new byte[]{0, 1};
            tempDOS = (DataOutputStream) tempSocket.getOutputStream();
            tempDOS.write(bytes);

            //send Client Identification
            bytes = new byte[]{0, 2, 2, 19, 55};
            tempDOS = (DataOutputStream) tempSocket.getOutputStream();
            tempDOS.write(bytes);

            //send Client Authentication
            bytes = new byte[]{0, 3, 0, 1, 42};
            tempDOS = (DataOutputStream) tempSocket.getOutputStream();
            tempDOS.write(bytes);

            //set attributes
            socket = tempSocket;
            in = (DataInputStream) socket.getInputStream();
            out = (DataOutputStream) socket.getOutputStream();

            startInputHandler();
            connected = true;
        } catch (Throwable t) {
            if (t.getClass().equals(ConnectionException.class)) {
                throw (ConnectionException) t;
            }

            t.printStackTrace();
            System.exit(-1);
        }
    }

    /**
     * Wechselt die Verbindung zu einem anderen Chatpartner
     * @param partnerID
     * @throws ConnectionException
     */
    public void switchConnection(int partnerID) throws ConnectionException{
        try {
            if (!connected) {
                connect();
            }

            // TODO: Teile dem Server mit, dass du dich mit dem Chatpartner mit ID 'partnerID' verbinden möchtest
            //  und stelle sicher, dass der Server dies acknowledgt.

        } catch (Throwable t) {

            if (t.getClass().equals(ConnectionException.class)) {
                throw (ConnectionException)t;
            }
            t.printStackTrace();
            System.exit(-1);
        }
    }

    /**
     * Sende eine Nachricht an den momentan ausgewählten Nutzer.
     * @param message
     */
    public void sendMessage(String message) {
        try {
            // Kodiert die übergebene 'message' in UTF-8
            byte[] buf = StandardCharsets.UTF_8.encode(message).array();
            int length = Math.min(buf.length, 0xffff);

            // TODO: Sende die übergebene Message

        } catch (Throwable t) {
            t.printStackTrace();
            System.exit(-1);
        }

    }


    /**
     * Holt sich length bytes vom empfänger Thread
     * @param length anzahl an bytes
     * @return
     */
    private byte[] getResponse(int length) {

        boolean wait = true;
        byte[] resp = new byte[length];

        synchronized(handshakeMutex) {
            wait = handshakeMutex.size() < length;
        }

        while (wait) {
            synchronized(inputHandler) {
                try {
                    inputHandler.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                    System.exit(-1);
                }
            }
            synchronized(handshakeMutex) {
                wait = handshakeMutex.size() < length;
            }
        }

        synchronized(handshakeMutex) {
            for (int i = 0; i < resp.length; i++) {
                resp[i] = handshakeMutex.remove();
            }
        }
        return resp;
    }

    /**
     * Startet einen neuen thread für das input handling.
     */
    private void startInputHandler() {

        inputHandler = new Thread() {
            @Override
            public void run() {
                handleInput();
            }
        };
        inputHandler.start();

    }

    /**
     * Übergibt eine Nachricht an die Nutzeroberfläche
     * @param content Nachrichten inhalt
     */
    private void displayMessage(String content) {
        Platform.runLater(() -> {
            ViewController.displayMessage(ViewController.currentChat, new Message(LocalDateTime.now(), content, false, 0));
        });
    }

    /**
     * Übergibt eine Handshake Nachricht an den Hauptthread
     * @param handshake Nachricht
     */
    private void passHandshakeMessage(byte[] handshake) {
        synchronized(handshakeMutex) {

            for (byte b : handshake) {
                handshakeMutex.add(b);
            }
        }

        synchronized(inputHandler) {
            inputHandler.notifyAll();
        }
        System.out.println("Notified main thread");
    }

    /**
     * Setter fürs testing
     * @param client
     */
    public void setClient(HttpClient client) {
        this.client = client;
    }
    
    /**
     * Schlißet offene Verbindungen
     */
    public void close() {
        if (inputHandler != null) {
            inputHandler.interrupt();
        }
        if (socket != null) {
            try {
                out.write(new byte[] {0,-1});
                socket.close();
            } catch (IOException e) {
                // pass
            }
        }
    }

    public static class ConnectionException extends Exception {

        private static final long serialVersionUID = 9055969838018372992L;

        public ConnectionException() {super();}
        public ConnectionException(String message) {super(message);}

    }
}