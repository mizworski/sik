#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>

#include <limits.h>
#include <poll.h>
#include <iostream>
#include<ctime>
#include <set>
#include <deque>
#include <cstring>
#include <queue>
#include <map>
#include <fstream>
#include <sstream>
#include <arpa/inet.h>

const int32_t FAILURE = 1;
const int32_t DATAGRAM_BUFFER_SIZE = 4096;
const int32_t MAX_UDP_PACKET_SIZE = 65507;
const int32_t MSG_WITHOUT_FILE_SIZE = 9;

struct message {
    uint64_t timestamp;
    char ch;
};

std::vector<unsigned char> intToBytes(uint64_t paramInt) {
    std::vector<unsigned char> arrayOfByte(8);
    for (int i = 0; i < 8; i++)
        arrayOfByte[7 - i] = (unsigned char) (paramInt >> (i * 8));
    return arrayOfByte;
}

std::string getString(const std::string &filename) {
    std::streampos size;
    char *memblock;
    std::ifstream file(filename, std::ios_base::in | std::ios_base::binary | std::ios_base::ate);
    if (file.is_open()) {
        size = file.tellg();
        memblock = new char[size];
        file.seekg(0, std::ios_base::beg);
        file.read(memblock, size);
        file.close();
    } else {
        throw std::runtime_error("Couldn't open file");
    }
    std::string res(memblock);
    delete[] memblock;

    if (res.size() + 1 > MAX_UDP_PACKET_SIZE - MSG_WITHOUT_FILE_SIZE) {
        throw std::runtime_error("File is too large to fit into datagram");
    }

    return res;
}

void initialize_connection(sockaddr_in &server_address, pollfd *sockets, const std::string &port_str) {
    sockets[0].events = POLLIN;
    sockets[0].revents = 0;

    for (int i = 1; i < _POSIX_OPEN_MAX; ++i) {
        sockets[i].events = POLLOUT;
        sockets[i].revents = 0;
    }

    for (int i = 0; i < _POSIX_OPEN_MAX; ++i) {
        sockets[i].fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockets[i].fd < 0) {
            throw std::runtime_error("Failed to open socket");
        }
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(((uint16_t) stoi(port_str)));
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockets[0].fd, (struct sockaddr *) &server_address, (socklen_t) sizeof(server_address)) < 0) {
        throw std::runtime_error("Failed to bind socket");
    }
}

message &deserialize_message(const unsigned char *raw_msg, message &msg) {
    msg.timestamp = 0;

    int32_t mult = 1;
    for (int i = 0; i < 8; ++i) {
        msg.timestamp += raw_msg[i] * mult;
        mult *= 256;
    }
    msg.ch = raw_msg[8];
    return msg;
}

void process_message(std::map<std::pair<in_addr_t, in_port_t>, std::pair<time_t, sockaddr_in>> &clients,
                     std::vector<std::pair<time_t, message>> &datagrams,
                     std::deque<std::pair<std::pair<int, time_t>, sockaddr_in>> &messages_to_send, int read_index,
                     const sockaddr_in &client_address, time_t current_time, const message &msg) {
    time_t msg_timestamp = msg.timestamp;
    struct tm *msg_time_info = gmtime(&msg_timestamp);
    const int32_t time_year = msg_time_info->tm_year + 1900;
    if (time_year < 1717 || time_year > 4242) {
        std::cerr << "Wrong timestamp year in message" << std::endl;
        std::cerr << "Src: " << inet_ntoa(client_address.sin_addr) << ":" << client_address.sin_port << std::endl;
    } else {
        datagrams.at(read_index) = {current_time, msg};
        for (auto it = clients.begin(); it != clients.end();) {
            if ((current_time - (*it).second.first) > 120) {
                clients.erase(it++);
            } else {
                if (client_address.sin_port != (*it).second.second.sin_port ||
                    client_address.sin_addr.s_addr != (*it).second.second.sin_addr.s_addr) {
                    messages_to_send.push_back({{read_index, current_time}, (*it).second.second});
                }
                ++it;
            }
        }
        read_index = (read_index + 1) % DATAGRAM_BUFFER_SIZE;
    }
}

void try_send_message(std::string &file_content, std::vector<std::pair<time_t, message>> &datagrams,
                      std::deque<std::pair<std::pair<int, time_t>, sockaddr_in>> &messages_to_send, pollfd &socket) {
    if (!messages_to_send.empty()) {
        while (datagrams.at((unsigned long) messages_to_send.front().first.first).first !=
               messages_to_send.front().first.second) { /// If message is still stored in buffer
            messages_to_send.pop_front();
        }

        struct message msg = datagrams.at((unsigned long) messages_to_send.front().first.first).second;
        std::ostringstream os;
        auto msg_timestamp_bytes = intToBytes(htobe64(msg.timestamp));
        for (auto byte : msg_timestamp_bytes) {
            os << byte;
        }
        os << msg.ch << file_content.data() << '\0';
        std::__cxx11::string message(os.str());
        int sflags = 0;
        socklen_t snda_len = (socklen_t) message.size();
        ssize_t snd_len = sendto(socket.fd, message.c_str(), (size_t) snda_len, sflags,
                                 (struct sockaddr *) &(messages_to_send.front().second), snda_len);

        if (snd_len != snda_len) {
            throw std::runtime_error("error on sending datagram to client socket");
        };
        messages_to_send.pop_front();
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Wrong number of arguments" << std::endl;
        return FAILURE;
    }

    struct sockaddr_in server_address;
    struct pollfd sockets[_POSIX_OPEN_MAX];
    const std::string port_str(argv[1]);
    const std::string filename(argv[2]);

    std::string file_content = getString(filename);

    try {
        initialize_connection(server_address, sockets, port_str);
    } catch (std::runtime_error e) {
        std::cerr << e.what() << std::endl;
        return FAILURE;
    }

    std::map<std::pair<in_addr_t, in_port_t>, std::pair<time_t, struct sockaddr_in>> clients;
    std::vector<std::pair<time_t, struct message>> datagrams(DATAGRAM_BUFFER_SIZE);
    std::deque<std::pair<std::pair<int, time_t>, struct sockaddr_in>> messages_to_send;

    int read_index = 0;

    while (true) {
        for (int i = 0; i < _POSIX_OPEN_MAX; ++i) {
            sockets[i].revents = 0;
        }

        int ret;
        if (messages_to_send.empty()) {
            ret = poll(sockets, 1, 5000);
        } else {
            ret = poll(sockets, _POSIX_OPEN_MAX, 5000);
        }
        if (ret < 0) {
            std::cerr << "Error while polling" << std::endl;
            return FAILURE;
        } else if (ret > 0) {
            if (sockets[0].revents & POLLIN) {
                unsigned char raw_msg[MAX_UDP_PACKET_SIZE];
                struct sockaddr_in client_address;
                socklen_t rcva_len = (socklen_t) sizeof(client_address);
                int flags = 0;
                ssize_t len = recvfrom(sockets[0].fd, &raw_msg, MAX_UDP_PACKET_SIZE, flags,
                                       (struct sockaddr *) &client_address, &rcva_len);

                time_t current_time = std::time(0);
                clients.insert({{client_address.sin_addr.s_addr, client_address.sin_port},
                                {current_time,                   client_address}});
                if (len < 0) {
                    std::cerr << "Error while reading" << std::endl;
                    return FAILURE;
                } else if (len != MSG_WITHOUT_FILE_SIZE) {
                    std::cerr << "Wrong message received: not valid length." << std::endl;
                    std::cerr << "Src: " << inet_ntoa(client_address.sin_addr) << ":" << client_address.sin_port
                              << std::endl;
                } else {
                    struct message msg;
                    msg = deserialize_message(raw_msg, msg);

                    process_message(clients, datagrams, messages_to_send,
                                    read_index, client_address, current_time, msg);
                }
            }

            for (int i = 1; i < _POSIX_OPEN_MAX; ++i) {
                if (sockets[i].revents & POLLOUT) {
                    try {
                        try_send_message(file_content, datagrams, messages_to_send, sockets[i]);
                    } catch (std::runtime_error e) {
                        std::cerr << e.what() << std::endl;
                        return FAILURE;
                    }
                }
            }
        }
    }

    return 0;
}
