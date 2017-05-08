#include <iostream>
#include <sstream>
#include <cstring>
#include <netdb.h>
#include <vector>

const int FAILURE = 1;
const int MAX_UDP_PACKET_SIZE = 65507;

struct message {
    uint64_t timestamp;
    char ch;
    std::string file;
};

void init_addr_hints(struct addrinfo &addr_hints) {
    memset(&addr_hints, 0, sizeof(struct addrinfo));

    addr_hints.ai_flags = 0;
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_DGRAM;
    addr_hints.ai_protocol = IPPROTO_UDP;

    addr_hints.ai_addrlen = 0;
    addr_hints.ai_addr = NULL;
    addr_hints.ai_canonname = NULL;
    addr_hints.ai_next = NULL;
}

std::vector<unsigned char> intToBytes(uint64_t paramInt) {
    std::vector<unsigned char> arrayOfByte(8);
    for (int i = 0; i < 8; i++)
        arrayOfByte[7 - i] = (unsigned char) (paramInt >> (i * 8));
    return arrayOfByte;
}

void parse_message(std::string timestamp_str, const char msg_char, message &message) {
    uint64_t timestamp = std::stoull(timestamp_str);
    time_t raw_time = timestamp;
    struct tm *time_info = gmtime(&raw_time);

    const int32_t time_year = time_info->tm_year + 1900;
    if (time_year < 1717 || time_year > 4242) {
        throw std::runtime_error("Wrong timestamp year");
    }

    message.timestamp = htobe64(timestamp);
    message.ch = msg_char;
}

void initialize_connection(addrinfo &addr_hints, addrinfo *&addr_result, const std::string &host_str,
                           const std::string &port_str, sockaddr_in &my_address, int32_t &sock) {
    if (getaddrinfo(host_str.c_str(), NULL, &addr_hints, &addr_result) != 0) {
        throw std::runtime_error("Failed to get address of server.");
    }

    my_address.sin_family = AF_INET; // IPv4
    my_address.sin_addr.s_addr = ((struct sockaddr_in *) (addr_result->ai_addr))->sin_addr.s_addr;
    my_address.sin_port = htons((uint16_t) stoi(port_str));

    freeaddrinfo(addr_result);

    /// Open socket
    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        throw std::runtime_error("Failed to open socket.");
    }
}

std::string &serialize_message(const message &msg, std::string &message) {
    std::ostringstream os;
    auto msg_timestamp_bytes = intToBytes(msg.timestamp);
    for (auto byte : msg_timestamp_bytes) {
        os << byte;
    }
    os << msg.ch;
    message = os.str();
    return message;
}

message &deserialize_message(const char *raw_msg, ssize_t rcv_len, message &msg) {
    msg.timestamp = 0;
    int32_t mult = 1;
    for (int i = 0; i < 8; ++i) {
            msg.timestamp += ((uint8_t) raw_msg[i]) * mult;
            mult *= 256;
        }
    msg.ch = raw_msg[8];


    size_t file_beg = 9;
    std::__cxx11::string file_content(raw_msg, rcv_len);
    msg.file = file_content.substr(file_beg);
    return msg;
}

int main(int argc, char *argv[]) {
    struct addrinfo addr_hints;
    struct addrinfo *addr_result;
    struct sockaddr_in my_address;
    int32_t sock;
    struct message msg;

    if (argc != 4 && argc != 5) {
        std::cerr << "Wrong number of arguments." << std::endl;
        return FAILURE;
    }

    init_addr_hints(addr_hints);
    std::string timestamp_str(argv[1]);
    const char msg_char = *argv[2];

    try {
        parse_message(timestamp_str, msg_char, msg);
    } catch (std::invalid_argument e) {
        std::cerr << "No conversion could be performed." << std::endl;
        return FAILURE;
    } catch (std::out_of_range e) {
        std::cerr << "Converted value fell out of the range of the result type." << std::endl;
        return FAILURE;
    } catch (std::runtime_error e) {
        std::cerr << e.what() << std::endl;
        return FAILURE;
    }

    /// Host and port
    std::string host_str(argv[3]);

    std::string port_str("20160");
    if (argc == 5) {
        port_str = argv[4];
    }

    try {
        initialize_connection(addr_hints, addr_result, host_str, port_str, my_address, sock);
    } catch (std::runtime_error e) {
        std::cerr << e.what() << std::endl;
        return FAILURE;
    }

    std::string message;

    message = serialize_message(msg, message);
    size_t msg_len = message.size();

    socklen_t rcv_address_len = (socklen_t) sizeof(my_address);
    ssize_t snd_len = sendto(sock, message.c_str(), msg_len, 0, (struct sockaddr *) &my_address, rcv_address_len);

    if (snd_len != (ssize_t) msg_len) {
        std::cerr << "Failed to send message." << std::endl;
        return FAILURE;
    }

    /// Receiving messages in endless loop
    while (true) {
        struct sockaddr_in server_address;
        char raw_msg[MAX_UDP_PACKET_SIZE];

        size_t rcv_msg_len = MAX_UDP_PACKET_SIZE;
        rcv_address_len = (socklen_t) sizeof(server_address);
        ssize_t rcv_len = recvfrom(sock, &raw_msg, rcv_msg_len, 0, (struct sockaddr *) &server_address,
                                   &rcv_address_len);

        if (rcv_len < 0) {
            std::cerr << "read." << std::endl;
            return FAILURE;
        }

        msg = deserialize_message(raw_msg, rcv_len, msg);

        std::cout << msg.timestamp << " " << msg.ch << " " << msg.file << "\n" << std::flush;
    }
}