import uuid
import random
import selectors
import socket
import struct
import sqlite3
import os
import time
from collections import namedtuple
from exceptions import *
from parameters import *


class Server:
    def __init__(self, ip):
        self.ip = ip
        self.port = self.get_server_port()
        self.version = 2    # version of server
        self.status = 0     # status code after processing request
        self.cur_cid = b''  # currently handled client id

        # open SQL database and create tables it they dont exist
        self.conn, self.cur = self.open_sql_db()

        # prepare a selector to handle multiple events from multiple users
        self.sel = selectors.DefaultSelector()

        # open server socket (TCP/IP non-blocking)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.ip, self.port))
        self.sock.listen(MAX_ACCEPTED_CONNECTIONS)
        self.sock.setblocking(False)

        # register read events on server socket
        self.sel.register(self.sock, selectors.EVENT_READ, self.accept)

    def get_server_port(self):
        """
        retrieves server port from the port.info file
        :return:
        """
        fh = open('port.info', 'r')
        info = fh.readline()
        fh.close()
        if not(info.isdecimal()) or not(0 < len(info) < 5):
            print('Error in port.info file')
            exit(1)
        return int(info)

    def open_sql_db(self):
        """
        opens a client database. create a clients table with the following entries
        ID - 16 bytes
        Name - 255 bytes
        Public Key - 160 bytes
        Last Seen - Date and Hour (last time a message was received from the client)

        also create a message table with the following entries
        ID - 4 bytes (index)
        ToClient - 16 bytes (destination clientID)
        FromClient - 16 bytes (source clientID)
        Type - 1 byte (message type)
        Content - Blob (Content of the message)
        :return:
        """
        if not os.path.exists(SERVER_DB):
            open(SERVER_DB, 'ab')

        conn = sqlite3.connect(SERVER_DB)
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS clients (ID BLOB, Name BLOB, PublicKey BLOB, LastSeen TEXT)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS messages(ID BLOB, ToClient BLOB, FromClient BLOB, Type BLOB, Content BLOB)''')
        conn.commit()
        print('Created Clients and Messages Tables')
        return conn, cur

    def accept(self, sock, mask):
        """
        Accepts incoming client connections
        Sets the new connection to be in blocking mode
        in order to avoid:
        BlockingIOError: [WinError 10035]
        "A non-blocking socket operation could not be completed immediately"
        This is the event function that is being triggered upon a
        read event in selector.
        :param sock: this server's socket
        :param mask: Event mask
        :return:
        """
        conn, addr = sock.accept()  # Should be ready
        print(f'Accepted client from address: {addr}')
        conn.setblocking(True)
        self.sel.register(conn, selectors.EVENT_READ, self.recv_request)

    def send(self, conn, mask, data, amount) -> int:
        """
        send given data to client connection object.
        :returns number of bytes sent
        """
        sent = conn.send(data)
        if sent != amount:
            raise SentToFewBytes('amount of bytes sent not equal to amount specified')
        return sent

    def recv_request(self, conn, mask):
        """
        After successful client connection, this method will
        be invoked in order to handle client's request.
        First, receive the header of the request.
        Then, process the header content.
        And finally, close the connection to client.
        """
        try:
            header = self.recv_header(conn, mask)  # Should be ready
            Header = namedtuple('Header', ['client_id', 'version', 'op_code', 'payload_size'])
            uh = Header._make(self.parse_header(header))

            self.process_request(conn, mask, uh)

        except Exception as err:
            print(err)
        finally:
            print('Done processing client request')
            self.shutdown_client(conn)

    def recv_header(self, conn, mask) -> bytes:
        """
        receive the header of the message
        :returns header (bytes object)
        """
        header = conn.recv(REQUEST_HEADER_SIZE)
        if header:
            pass
            # print(f'Received request header from client {conn}:\n{repr(header)}')
            # print(f'Size {len(header)}')
        else:
            raise HeaderMissing('Missing header in received packet')
        if len(header) != REQUEST_HEADER_SIZE:
            raise ReceivedToFewBytes(f'Did not received correct amount of bytes for header: {REQUEST_HEADER_SIZE}')
        return header

    def recv_payload(self, conn, mask, size) -> bytes:
        """
        receive the payload of the client. size specifies the amount
        of bytes of the payload.
        :param size: size of the payload
        :param conn: connection object to client
        :param mask: Event mask
        :returns payload (bytes object)
        """
        data = conn.recv(size)  # Should be ready
        if data or size == 0:
            pass
            # print(f'Received payload:\n{repr(data)}')
            # print(f'Size {len(data)}')
        else:
            raise PayloadMissing('Missing payload in received packet')
        if len(data) != size:
            raise ReceivedToFewBytes(f'Number of received bytes not equal to amount specified: {len(data)} !=  {size}')
        return data

    def process_request(self, conn, mask, uh):
        """
        Act accordingly to the received request operation from client
        uh = unpacked header after named tuple
        """
        print(f'Received operation: {uh.op_code}')

        if uh.op_code == REGISTER_REQUEST_CODE:
            self.registration_request(conn, mask, uh)
            self.response_registration(conn, mask)

        elif uh.op_code == CLIENTS_LIST_REQUEST_CODE:
            self.clients_list_request(uh)
            size_payload = (self.get_num_client_row() - 1) * (UUID_SIZE + MAX_ALLOWED_USERNAME)
            self.response_clients_list(conn, mask, size_payload)

        elif uh.op_code == PUBLIC_KEY_REQUEST_CODE:
            self.response_public_key(conn, mask, self.public_key_request(conn, mask, uh))

        elif uh.op_code == WAITING_MESSAGES_REQUEST_CODE:
            self.pull_waiting_message_request(conn, mask, uh)
            self.response_waiting_messages(conn, mask)

        elif uh.op_code == SEND_MESSAGE_REQUEST_CODE:
            dest_id, msg_id = self.send_message_request(conn, mask, uh)
            self.response_message(conn, mask, dest_id, msg_id)
        else:
            raise UnknownOperation('Received unknown operation code in header')

    def response_registration(self, conn, mask):
        """
        response from the server for recently registered/un-registered client
        """
        res_head = struct.pack('<BHI', self.version, self.status, UUID_SIZE)
        res_cid = struct.pack(f'<{UUID_SIZE}s', self.cur_cid)
        self.send(conn, mask, res_head, RESPONSE_HEADER_SIZE)
        self.send(conn, mask, res_cid, UUID_SIZE)

    def response_clients_list(self, conn, mask, size):
        """
        server response: send all clients in clients table without current client
        """
        if self.status == SERVER_ERROR_CODE:
            self.response_error(conn, mask)
        else:
            res_head = struct.pack('<BHI', self.version, self.status, size)
            res_cid = struct.pack(f'<{UUID_SIZE}s', self.cur_cid)
            self.send(conn, mask, res_head, RESPONSE_HEADER_SIZE)
            self.send(conn, mask, res_cid, UUID_SIZE)

            if size == 0:  # no other clients exist in database
                return

            print('Yielding client id and name of all clients in DB')
            for row in self.row_generator('clients'):
                if row[0] != self.cur_cid:
                    # uuid, name: row[0], row[1]
                    res_payload = struct.pack(f'<{UUID_SIZE}s', row[0])
                    self.send(conn, mask, res_payload, UUID_SIZE)
                    res_payload = struct.pack(f'<{MAX_ALLOWED_USERNAME}s', row[1])
                    self.send(conn, mask, res_payload, MAX_ALLOWED_USERNAME)

    def response_public_key(self, conn, mask, dest_uuid):
        """
        server response with public key of a given client
        """
        if self.status == SERVER_ERROR_CODE or dest_uuid is None:
            self.response_error(conn, mask)
        else:
            res_head = struct.pack('<BHI', self.version, self.status, UUID_SIZE + PUB_KEY_SIZE)
            res_cid = struct.pack(f'<{UUID_SIZE}s', self.cur_cid)
            self.send(conn, mask, res_head, RESPONSE_HEADER_SIZE)
            self.send(conn, mask, res_cid, UUID_SIZE)

            self.cur.execute("SELECT PublicKey FROM clients WHERE ID=:uuid", {"uuid": dest_uuid})
            public_key = self.cur.fetchall()[0][0]
            self.send(conn, mask, public_key, PUB_KEY_SIZE)

    def response_waiting_messages(self, conn, mask):
        """
        server response for pulling waiting messages from messages table.
        send all message rows that belong to the current client.
        afterwards, delete these rows from table.
        """
        if self.status == SERVER_ERROR_CODE:
            self.response_error(conn, mask)
            return

        # calculate the size of all waiting messages
        self.cur.execute("SELECT * FROM messages WHERE ToClient=:uuid", {"uuid": self.cur_cid})
        msg = self.cur.fetchone()
        size = 0
        while msg is not None:
            size += len(msg[4]) + UUID_SIZE + MSG_ID_SIZE + MSG_TYPE_SIZE  # sum content size and message header size
            msg = self.cur.fetchone()

        if size > (2**32):
            #  sum of all messages is too large
            self.status = SERVER_ERROR_CODE
            self.response_error(conn, mask)
            return

        # construct and send header  + client uuid
        res_head = struct.pack('<BHI', self.version, self.status, size)
        res_cid = struct.pack(f'<{UUID_SIZE}s', self.cur_cid)
        self.send(conn, mask, res_head, RESPONSE_HEADER_SIZE)
        self.send(conn, mask, res_cid, UUID_SIZE)

        # send all client's waiting messages
        # send message header fields in little endian
        # then send the message content
        self.cur.execute("SELECT * FROM messages WHERE ToClient=:uuid", {"uuid": self.cur_cid})
        msg = self.cur.fetchone()
        while msg is not None:
            self.send(conn, mask, msg[2], UUID_SIZE)  # source client
            self.send(conn, mask, msg[0], MSG_ID_SIZE)  # message id
            self.send(conn, mask, msg[3], MSG_TYPE_SIZE)  # message type
            self.send(conn, mask, struct.pack('<I', len(msg[4])), CONTENT_SIZE)  # size of content
            self.send(conn, mask, msg[4], len(msg[4]))  # content
            msg = self.cur.fetchone()  # fetch the next message

        #  delete all client's waiting messages
        self.cur.execute("DELETE FROM messages WHERE ToClient=:uuid", {"uuid": self.cur_cid})
        self.cur.fetchall()
        self.conn.commit()

    def response_message(self, conn, mask, dest_id, msg_id):
        """
        server response to send message: send back the destination client's uuid and message id
        as it is saved in the messages table.
        """
        if self.status == SERVER_ERROR_CODE:
            self.response_error(conn, mask)
        else:
            res_head = struct.pack('<BHI', self.version, self.status, UUID_SIZE + MSG_ID_SIZE)
            res_cid = struct.pack(f'<{UUID_SIZE}s', self.cur_cid)
            self.send(conn, mask, res_head, RESPONSE_HEADER_SIZE)
            self.send(conn, mask, res_cid, UUID_SIZE)

            self.send(conn, mask, dest_id, UUID_SIZE)
            self.send(conn, mask, msg_id, MSG_ID_SIZE)

    def response_error(self, conn, mask):
        """
        Send back an error code
        """
        res_head = struct.pack('<BHI', self.version, SERVER_ERROR_CODE, SERVER_ERROR_SIZE)
        res_cid = struct.pack(f'<{UUID_SIZE}s', self.cur_cid)
        self.send(conn, mask, res_head, RESPONSE_HEADER_SIZE)
        self.send(conn, mask, res_cid, UUID_SIZE)

    def parse_header(self, header) -> tuple:
        """
        unpack the header:
        16 bytes of client_id
        1 byte version
        2 bytes operation code
        4 bytes payload size
        :param header:
        :returns unpacked header iterable
        """
        return struct.unpack('<16sBHI', header)

    def parse_payload(self, payload, **kwargs) -> tuple:
        """
        gets the payload bytes object, and unpacks it in a way
        that the resulted bytes would split into categories
        according to key word arguments provided.
        for example: unpack and split the payload into 2 categories.
        first 255 bytes are name, and the rest are id_num...
        :param payload: the actual payload
        :param kwargs: key value elements (categories in payload)
        :return: tuple that contains bytes objects of the payload,
        categorized (split) according the kwargs argument.
        """
        if len(payload) > sum(kwargs.values()):
            raise RuntimeError
        splitter = ''
        for num_bytes in kwargs.values():
            splitter += f'{num_bytes}s'
        return struct.unpack(splitter, payload)

    def registration_request(self, conn, mask, uh):
        """
        handles registration request. unpacks the payload from
        the client. payload consists of username and public key.
        if no errors appeared, add the new client to the clients data base table and
        return the generated uuid for the client. also update the status
        code accordingly.
        """
        payload = self.recv_payload(conn, mask, uh.payload_size)
        Payload = namedtuple('Payload', ['username', 'public_key'])
        up = Payload._make(self.parse_payload(payload,
                                              username_size=MAX_ALLOWED_USERNAME,
                                              public_key_size=PUB_KEY_SIZE))

        print('Searching DB for client existence')
        self.cur.execute("SELECT ID FROM clients WHERE ID=:uuid", {"uuid": uh.client_id})
        if not self.cur.fetchall():  # if == []
            uid = uuid.uuid4().bytes_le
            username = up.username
            print(f'Registering new client with uuid: {uid}')
            print(f'Public Key: {up.public_key}')

            self.cur.execute("INSERT INTO clients (ID, Name, PublicKey, LastSeen) VALUES (?, ?, ?, ?)",
                             (uid, username, up.public_key, time.ctime()))
            self.conn.commit()
            self.status = REGISTER_SUCCESS_STATUS
            self.cur_cid = uid
        else:
            print(f'Client already exists: {self.cur.fetchall()}, aborting registration')
            self.status = SERVER_ERROR_CODE
            self.cur_cid = uh.client_id

    def clients_list_request(self, uh):
        """
        check whether the current client exists in clients table.
        :param uh:
        :return:
        """
        print('Searching DB for client existence')
        self.cur_cid = uh.client_id
        self.cur.execute("SELECT ID FROM clients WHERE ID=:uuid", {"uuid": uh.client_id})

        if not self.cur.fetchall():  # if == []:
            print(f'Client {uh.client_id} does not exist, aborting operation')
            self.status = SERVER_ERROR_CODE
        else:
            self.status = CLIENTS_LIST_SUCCESS_STATUS

    def public_key_request(self, conn, mask, uh) -> bytes:
        """
        check if destination client exists, and returns his uuid
        """
        print('Searching DB for source client')
        self.cur_cid = uh.client_id
        self.cur.execute("SELECT ID FROM clients WHERE ID=:uuid", {"uuid": uh.client_id})

        if not self.cur.fetchall():  # if == []
            print(f'Client {uh.client_id} does not exist, aborting')
            self.status = SERVER_ERROR_CODE
        else:
            payload = self.recv_payload(conn, mask, PUBLIC_KEY_REQUEST_PAYLOAD)
            Payload = namedtuple('Payload', ['dest_uuid'])
            up = Payload._make(self.parse_payload(payload, dest_uuid=UUID_SIZE))

            print('Searching for destination client')
            self.cur.execute("SELECT ID FROM clients WHERE ID=:uuid", {"uuid": up.dest_uuid})
            if not self.cur.fetchall():
                print(f'Destination client with UUID: {up.dest_uuid} does not exist, aborting')
                self.status = SERVER_ERROR_CODE
            else:
                self.status = PUBLIC_KEY_SUCCESS_STATUS
                return up.dest_uuid

    def pull_waiting_message_request(self, conn, mask, uh):
        """
        check if current client exists
        """
        print('Searching DB for source client')
        self.cur_cid = uh.client_id
        self.cur.execute("SELECT ID FROM clients WHERE ID=:uuid", {"uuid": uh.client_id})

        if not self.cur.fetchall():  # if == []
            print(f'Client {uh.client_id} does not exist, aborting')
            self.status = SERVER_ERROR_CODE
        else:
            self.status = WAITING_MESSAGES_SUCCESS_STATUS

    def send_message_request(self, conn, mask, uh) -> (int, bytes):
        """
        receive the message header from client, and check if its valid.
        If so, call the receiving function.
        """
        print('Searching DB for source client')
        self.cur_cid = uh.client_id
        self.cur.execute("SELECT ID FROM clients WHERE ID=:uuid", {"uuid": uh.client_id})

        if not self.cur.fetchall():  # if == []
            print(f'Client {uh.client_id} does not exist, aborting')
            self.status = SERVER_ERROR_CODE
            return None, None

        # receive destination client uuid, message type, and content size of the message
        payload = self.recv_payload(conn, mask, UUID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE)
        Payload = namedtuple('Payload', ['dest_uuid', 'msg_type', 'content_size'])
        up = Payload._make(self.parse_payload(payload,
                                              dest_uuid=UUID_SIZE,
                                              msg_type=MSG_TYPE_SIZE,
                                              content_size=CONTENT_SIZE))

        dest_uuid = struct.unpack(f'<{UUID_SIZE}s', up.dest_uuid)[0]
        msg_type = struct.unpack('<B', up.msg_type)[0]
        content_size = struct.unpack('<I', up.content_size)[0]
        msg_id = b'\x00'

        print('Searching for destination client')
        self.cur.execute("SELECT ID FROM clients WHERE ID=:uuid", {"uuid": up.dest_uuid})
        if not self.cur.fetchall():
            print(f'Destination client with UUID: {up.dest_uuid} does not exist, aborting')
            self.status = SERVER_ERROR_CODE
            return None, None

        print('Message\n'
              f'Source client: {self.cur_cid}\n'
              f'Dest client:   {dest_uuid}\n'
              f'Message Type:  {msg_type}\n'
              f'Content Size:  {content_size}')

        if msg_type == SYMMETRIC_KEY_SEND_MSG_TYPE or\
           msg_type == SYMMETRIC_KEY_REQUEST_MSG_TYPE or \
           msg_type == TEXT_SEND_MSG_TYPE or \
           msg_type == FILE_SEND_MSG_TYPE:

            size, msg_id = self.recv_msg_and_upload_to_table(conn, mask, dest_uuid, msg_type, content_size)
            self.status = SEND_MESSAGE_SUCCESS_STATUS if size == content_size else SERVER_ERROR_CODE
        else:
            self.status = SERVER_ERROR_CODE
        return up.dest_uuid, msg_id

    def recv_msg_and_upload_to_table(self, conn, mask, dest_uuid, msg_type, content_size) -> (int, bytes):
        """
        Receive message payloads from client and save them to messages table in DB.
        The recipient of the messages is dest_uuid.
        Supports texts and files.
        Message will be saved in a single blob in a row.
        """
        source_uuid = self.cur_cid
        msg_id = struct.pack('<I', random.randrange(0, 2 ** 32))  # 4 bytes
        print(f'Attempting to receive content of size: {content_size} bytes')
        rounds = int(content_size / CHUNK_SIZE)
        content = b''
        size = 0
        n = 0

        while n < rounds:
            # time.sleep(0.01)
            chunk = self.recv_payload(conn, mask, CHUNK_SIZE)
            size += len(chunk)
            content += chunk
            n += 1

        # receive the remaining bytes
        chunk = self.recv_payload(conn, mask, content_size - size)
        size += len(chunk)
        content += chunk

        self.cur.execute("INSERT INTO messages (ID, ToClient, FromClient, Type, Content) VALUES (?, ?, ?, ?, ?)",
                         (msg_id, dest_uuid, source_uuid, struct.pack('<B', msg_type), content))

        print(f'Done receiving content. Received size: {size} bytes')
        self.conn.commit()
        return size, msg_id

    def row_generator(self, table):
        """
        generates rows from a given table in db.
        """
        for row in self.cur.execute(f"SELECT * FROM {table}"):
            yield row

    def get_num_client_row(self) -> int:
        """
        Return total number of client in table
        """
        try:
            self.cur.execute("SELECT * FROM clients")
            num_rows = len(self.cur.fetchall())
        except sqlite3.Error as err:
            print(err)
            num_rows = 0
        print(f'Total number of clients: {num_rows}')
        return num_rows

    def shutdown_client(self, conn):
        """
        close socket connection to client, and unregister the connection
        from any future events.
        :param conn: client's socket connection
        """
        print(f'Closing connection for client: {self.cur_cid}\n\n')
        self.sel.unregister(conn)
        conn.close()

    def close(self):
        """
        closes the selector, the socket, and the sql db
        """
        self.sel.close()
        self.sock.close()
        self.conn.close()

    def run(self):
        """
        listen for incoming events on this server's socket
        """
        print("Listening for connections on port ", self.port)
        while True:
            events = self.sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)


def main():
    server = Server('localhost')
    server.run()
    server.close()


if __name__ == '__main__':
    main()


