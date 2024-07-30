// https://www-numi.fnal.gov/offline_software/srt_public_context/WebDocs/Errors/unix_system_errors.html
// #define ENOENT           2      /* No such file or directory */
// #define EAGAIN          11      /* Try again */

#include "stdafx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>
#include <assert.h>

#include <sys/types.h>

#if defined(_WIN32)
#include <stdint.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <qos2.h>
#include <Windows.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "qwave.lib")
#pragma comment(lib, "crypt32.lib")
#else
#include <netdb.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif

#include <fcntl.h>
#include <errno.h>

#if defined(_MACOS)
#include <errno.h>
#elif defined(_LINUX)
#include <error.h>
#endif

#if defined(_WIN32)
#include <io.h>
#include <Windows.h>
#include <timeapi.h>
#include <mmsystem.h>
#else
#include <unistd.h>
#include <sched.h>
#include <pthread.h>

#if defined(_MACOS)
#include <libproc.h>
#endif

#if defined(_LINUX)
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/syscall.h>
#else
#include <mach-o/dyld.h>
#include <mach/thread_act.h>
#include <mach/mach_init.h>
#endif

#include <sys/resource.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#endif

#include <stdio.h>
#include <math.h>

#include <cmath>
#include <memory>
#include <cstdlib>
#include <chrono>

// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/ip.h#L26
// https://man7.org/linux/man-pages/man7/ip.7.html
#if defined(_WIN32)
#define IPTOS_TOS_MASK      0x1E
#define IPTOS_TOS(tos)      ((tos) & IPTOS_TOS_MASK)
#define IPTOS_LOWDELAY      0x10
#define IPTOS_THROUGHPUT    0x08
#define IPTOS_RELIABILITY   0x04
#define IPTOS_MINCOST       0x02
#endif

#include "aggligator.h"

namespace aggligator
{
    static bool                                                         SOCKET_FLASH_MODE = false;

    /* Refer:
     * https://github.com/torvalds/linux/blob/977b1ef51866aa7170409af80740788d4f9c4841/include/net/tcp.h#L287
     * https://lore.kernel.org/netdev/87pronqq04.fsf@chdir.org/T/
     * https://android.googlesource.com/kernel/mediatek/+/android-mtk-3.18/include/net/tcp.h?autodive=0%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F
     * https://elixir.bootlin.com/linux/v2.6.27-rc7/source/include/net/tcp.h
     *
     * The next routines deal with comparing 32 bit unsigned ints
     * and worry about wraparound (automatic with unsigned arithmetic).
     */    

    static inline bool                                                  before(uint32_t seq1, uint32_t seq2) noexcept
    {
        return (int32_t)(seq1 - seq2) < 0;
    }
    
    static inline bool                                                  after(uint32_t seq2, uint32_t seq1) noexcept
    {
        return before(seq1, seq2);
    }

    class aggligator::server
    {
    public:
        ~server() noexcept
        {
            close();
        }

        void                                                            close() noexcept
        {
            for (auto&& kv : acceptors_)
            {
                acceptor& acceptor = kv.second;
                boost::system::error_code ec;
                acceptor->cancel(ec);
                acceptor->close(ec);
            }

            acceptors_.clear();
        }

        boost::asio::ip::udp::endpoint                                  server_endpoint_;
        unordered_map<int, acceptor>                                    acceptors_;
        unordered_map<int, client_ptr>                                  clients_;
    };

    class aggligator::client : public std::enable_shared_from_this<client>
    {
    public:
        client(const std::shared_ptr<aggligator>& aggligator) noexcept
            : socket_(aggligator->context_)
            , app_(aggligator)
            , server_mode_(false)
            , local_port_(0)
            , remote_port_(0)
            , established_num_(0)
            , connections_num_(0)
            , handshakeds_num_(0)
            , last_(0)
        {

        }
        ~client() noexcept
        {
            close();
        }

        void                                                            close() noexcept;
        bool                                                            send(Byte* packet, int packet_length) noexcept;
        bool                                                            open(int connections, int bind_port, unordered_set<boost::asio::ip::tcp::endpoint>& servers) noexcept;
        bool                                                            loopback() noexcept;
        bool                                                            timeout() noexcept;
        bool                                                            update(uint32_t now_seconds) noexcept;

        boost::asio::ip::udp::endpoint                                  source_endpoint_;
        boost::asio::ip::udp::socket                                    socket_;
        std::shared_ptr<aggligator>                                     app_;
        std::shared_ptr<convergence>                                    convergence_;
        deadline_timer                                                  timeout_;
        unordered_set<boost::asio::ip::tcp::endpoint>                   server_endpoints_;

        list<connection_ptr>                                            connections_;
        bool                                                            server_mode_     = false;
        int                                                             local_port_      = 0;
        uint16_t                                                        remote_port_     = 0;
        uint32_t                                                        established_num_ = 0;
        uint32_t                                                        connections_num_ = 0;
        uint32_t                                                        handshakeds_num_ = 0;
        uint32_t                                                        last_            = 0;
    };

    class aggligator::convergence
    {
    public:
        struct recv_packet
        {
            uint32_t                                                    seq    = 0;
            int                                                         length = 0;
            std::shared_ptr<Byte>                                       packet;
            boost::asio::ip::udp::endpoint                              dst;
        };

        queue<send_packet>                                              send_queue_;
        queue<recv_packet>                                              recv_queue_;
        uint32_t                                                        seq_no_         = 0;
        uint32_t                                                        ack_no_         = 1;
        bool                                                            wraparound_     = false;
        int                                                             rq_congestions_ = 0;
        std::shared_ptr<client>                                         client_;
        std::shared_ptr<aggligator>                                     app_;

        convergence(const std::shared_ptr<aggligator>& aggligator, const std::shared_ptr<client>& client) noexcept
            : wraparound_(false)
            , rq_congestions_(0)
            , client_(client)
            , app_(aggligator)
        {
            seq_no_ = (uint32_t)RandomNext(UINT16_MAX, INT32_MAX);
            ack_no_ = 0;
        }
        ~convergence() noexcept
        {
            close();
        }

        void                                                            close() noexcept;
        void                                                            emplace_wraparound(std::list<recv_packet>& queue, const recv_packet& packet) noexcept
        {
            for (;;)
            {
                auto tail = queue.begin();
                if (tail == queue.end())
                {
                    queue.emplace_back(packet);
                    break;
                }

                auto position = std::upper_bound(queue.rbegin(), queue.rend(), packet,
                    [this](const recv_packet& lhs, const recv_packet& rhs) noexcept
                    {
                        return after(lhs.seq, rhs.seq);
                    });

                queue.emplace(position.base(), packet);
                break;
            }
        }
        void                                                            emplace(std::list<recv_packet>& queue, const recv_packet& packet) noexcept
        {
            for (;;)
            {
                auto tail = queue.begin();
                if (tail == queue.end())
                {
                    queue.emplace_back(packet);
                    break;
                }

                if (tail->seq > packet.seq)
                {
                    queue.emplace_front(packet);
                    break;
                }

                auto rtail = queue.rbegin();
                if (rtail->seq <= packet.seq)
                {
                    queue.emplace_back(packet);
                    break;
                }

                if ((packet.seq - tail->seq) > (rtail->seq - packet.seq))
                {
                    auto position = std::upper_bound(queue.rbegin(), queue.rend(), packet,
                        [](const recv_packet& lhs, const recv_packet& rhs) noexcept
                        {
                            return lhs.seq > rhs.seq;
                        });

                    queue.emplace(position.base(), packet);
                }
                else
                {
                    auto position = std::lower_bound(queue.begin(), queue.end(), packet,
                        [](const recv_packet& lhs, const recv_packet& rhs) noexcept
                        {
                            return lhs.seq < rhs.seq;
                        });

                    queue.emplace(position, packet);
                }

                break;
            }
        }
        static std::shared_ptr<Byte>                                    pack(Byte* packet, int packet_length, uint32_t seq, int& out) noexcept;
        bool                                                            process(Byte* packet, int packet_length, bool dont_control) noexcept
        {
            bool ok = output(packet, packet_length);
            if (ok)
            {
                if (dont_control)
                {
                    return true;
                }

                if (++ack_no_ == 0)
                {
                    wraparound_ = false;
                }

                return rq_congestions_-- > 0;
            }

            return false;
        }
        bool                                                            input(Byte* packet, int packet_length) noexcept;
        bool                                                            output(Byte* packet, int packet_length) noexcept;
    };

    class aggligator::connection : public std::enable_shared_from_this<connection>
    {
    public:
        connection(const std::shared_ptr<aggligator>& aggligator, const client_ptr& client, const convergence_ptr& convergence) noexcept
            : app_(aggligator)
            , convergence_(convergence)
            , client_(client)
            , sending_(false)
            , next_(0)
        {

        }
        ~connection() noexcept
        {
            close();
        }

#if defined(_WIN32)
        class QoSS final
        {
        public:
            QoSS(int fd) noexcept
                : fd_(fd)
                , h_(NULL)
                , f_(NULL)
            {

            }
            ~QoSS() noexcept
            {
                if (NULL != h_)
                {
                    if (f_ != 0)
                    {
                        QOSRemoveSocketFromFlow(h_, fd_, f_, 0);
                    }

                    QOSCloseHandle(h_);
                }
            }

        public:
            static std::shared_ptr<QoSS>                                New(int fd, const boost::asio::ip::address& host, int port) noexcept { return New(fd, host, port, false); }
            static std::shared_ptr<QoSS>                                New(int fd) noexcept { return New(fd, boost::asio::ip::address_v4::any(), 0, true); }

        private:
            static std::shared_ptr<QoSS>                                New(int fd, const boost::asio::ip::address& host, int port, bool noaddress) noexcept
            {
                if (fd == INVALID_SOCKET)
                {
                    return NULL;
                }

                std::shared_ptr<QoSS> qos = make_shared_object<QoSS>(fd);
                if (NULL == qos)
                {
                    return NULL;
                }

                QOS_VERSION ver = { 1, 0 };
                if (!QOSCreateHandle(&ver, &qos->h_))
                {
                    return NULL;
                }

                if (noaddress)
                {
                    if (!QOSAddSocketToFlow(qos->h_, fd, NULL, QOSTrafficTypeControl, QOS_NON_ADAPTIVE_FLOW, &qos->f_))
                    {
                        return NULL;
                    }
                }
                else
                {
                    if (port <= 0 || port > UINT16_MAX)
                    {
                        return NULL;
                    }

                    if (!host.is_v4() && !host.is_v6())
                    {
                        return NULL;
                    }

                    if (ip_is_invalid(host))
                    {
                        return NULL;
                    }

                    if (host.is_v4())
                    {
                        sockaddr_in in{};
                        in.sin_family = AF_INET;
                        in.sin_port = htons(port);
                        in.sin_addr.s_addr = htonl(host.to_v4().to_uint());

                        if (!QOSAddSocketToFlow(qos->h_, fd, reinterpret_cast<sockaddr*>(&in), QOSTrafficTypeControl, QOS_NON_ADAPTIVE_FLOW, &qos->f_))
                        {
                            return NULL;
                        }
                    }
                    else
                    {
                        sockaddr_in6 in6{};
                        in6.sin6_family = AF_INET6;
                        in6.sin6_port = htons(port);
                        memcpy(&in6.sin6_addr, host.to_v6().to_bytes().data(), sizeof(in6.sin6_addr));

                        if (!QOSAddSocketToFlow(qos->h_, fd, reinterpret_cast<sockaddr*>(&in6), QOSTrafficTypeControl, QOS_NON_ADAPTIVE_FLOW, &qos->f_))
                        {
                            return NULL;
                        }
                    }
                }

                // We shift the complete ToS value by 3 to get rid of the 3 bit ECN field
                DWORD dscp = 26;

                // Sets DSCP to the same as Linux
                // This will fail if we're not admin, but we ignore it
                if (!QOSSetFlow(qos->h_, qos->f_, QOSSetOutgoingDSCPValue, sizeof(DWORD), &dscp, 0, NULL))
                {
                    return NULL;
                }

                return qos;
            }

        private:
            int                                                         fd_ = -1;
            void*                                                       h_  = NULL;
            DWORD                                                       f_  = 0;
        };
#endif

        void                                                            close() noexcept
        {
#if defined(_WIN32)
            qoss_.reset();
#endif

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::move(socket_);
            socket_.reset();

            if (socket)
            {
                aggligator::socket_close(*socket);
            }

            std::shared_ptr<aggligator> aggligator = app_;
            app_.reset();

            convergence_ptr convergence = std::move(convergence_);
            convergence_.reset();

            next_packet_.reset();
            if (convergence)
            {
                convergence->close();
            }

            client_ptr client = std::move(client_);
            client_.reset();

            if (client)
            {
                client->close();
            }
        }
        bool                                                            sent(const std::shared_ptr<Byte>& packet, int length) noexcept
        {
            ptr aggligator = app_;
            if (!aggligator)
            {
                return false;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
            if (!socket)
            {
                return false;
            }

            bool opened = socket->is_open();
            if (!opened)
            {
                return false;
            }

            auto self = shared_from_this();
            boost::asio::async_write(*socket, boost::asio::buffer(packet.get(), length),
                [self, this, packet, length](boost::system::error_code ec, std::size_t sz) noexcept
                {
                    bool processed = false;
                    sending_ = false;

                    if (ec == boost::system::errc::success)
                    {
                        ptr aggligator = app_;
                        if (aggligator)
                        {
                            aggligator->tx_ += sz;
                            aggligator->tx_pps_++;
                            processed = next();
                        }
                    }

                    if (!processed)
                    {
                        close();
                    }
                    
                    return processed;
                });

            sending_ = true;
            return true;
        }
        bool                                                            next() noexcept
        {
            convergence_ptr convergence = convergence_;
            if (!convergence)
            {
                return false;
            }
            else
            {
                std::shared_ptr<Byte> next_packet = std::move(next_packet_);
                next_packet_.reset();

                if (next_packet)
                {
                    return sent(next_packet, 2);
                }
            }

            auto tail = convergence->send_queue_.begin();
            auto endl = convergence->send_queue_.end();
            if (tail == endl)
            {
                return true;
            }

            send_packet context = *tail;
            convergence->send_queue_.erase(tail);

            return sent(context.packet, context.length);
        }
        bool                                                            recv() noexcept
        {
            std::shared_ptr<aggligator> aggligator = app_;
            if (!aggligator)
            {
                close();
                return false;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
            if (!socket)
            {
                close();
                return false;
            }

            bool opened = socket->is_open();
            if (!opened)
            {
                close();
                return false;
            }

            auto self = shared_from_this();
            boost::asio::async_read(*socket, boost::asio::buffer(buffer_, 2),
                [self, this, socket](boost::system::error_code ec, std::size_t sz) noexcept
                {
                    ptr aggligator = app_;
                    if (!aggligator)
                    {
                        close();
                        return false;
                    }

                    aggligator->rx_ += sz;
                    if (sz != 2)
                    {
                        close();
                        return false;
                    }

                    client_ptr client = client_;
                    if (!client)
                    {
                        close();
                        return false;
                    }

                    std::size_t length = buffer_[0] << 8 | buffer_[1];
                    if (length == 0)
                    {
                        if (!recv())
                        {
                            close();
                            return false;
                        }
                        else
                        {
                            aggligator->rx_pps_++;
                        }

                        client->last_ = (uint32_t)(aggligator->now() / 1000);
                        return true;
                    }

                    boost::asio::async_read(*socket, boost::asio::buffer(buffer_, length),
                        [self, this, length](boost::system::error_code ec, std::size_t sz) noexcept
                        {
                            ptr aggligator = app_;
                            if (!aggligator)
                            {
                                close();
                                return false;
                            }

                            aggligator->rx_ += sz;
                            if (length != sz)
                            {
                                close();
                                return false;
                            }

                            client_ptr client = client_;
                            if (!client)
                            {
                                close();
                                return false;
                            }

                            convergence_ptr convergence = convergence_;
                            if (!convergence)
                            {
                                close();
                                return false;
                            }
                            else
                            {
                                aggligator->rx_pps_++;
                            }

                            bool ok = convergence->input(buffer_, length) && recv();
                            if (ok)
                            {
                                client->last_ = (uint32_t)(aggligator->now() / 1000);
                            }
                            else
                            {
                                close();
                                return false;
                            }

                            return ok;
                        });
                    return true;
                });
            return true;
        }
        bool                                                            open(const boost::asio::ip::tcp::endpoint& server, const std::function<void(connection*)>& established) noexcept
        {
            std::shared_ptr<aggligator> aggligator = app_;
            if (!aggligator)
            {
                return false;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
            if (!socket)
            {
                socket = make_shared_object<boost::asio::ip::tcp::socket>(aggligator->context_);
                if (!socket)
                {
                    return false;
                }
            }

            if (socket->is_open())
            {
                return false;
            }

            boost::system::error_code ec;
            socket->open(server.protocol(), ec);

            if (ec)
            {
                return false;
            }
            else
            {
                aggligator::socket_adjust(*socket);
            }

#if defined(_WIN32)
            qoss_ = QoSS::New(socket->native_handle(), server.address(), server.port());
#endif
            socket_ = socket;
            socket->async_connect(server,
                [self = shared_from_this(), this, established](boost::system::error_code ec) noexcept
                {
                    ptr aggligator = app_;
                    if (!aggligator)
                    {
                        close();
                        return false;
                    }

                    if (ec)
                    {
                        close();
                        return false;
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
                    if (!socket)
                    {
                        close();
                        return false;
                    }

                    boost::asio::spawn(
                        [self, this, established](const boost::asio::yield_context& y) noexcept
                        {
                            if (!establish(y, established))
                            {
                                close();
                            }
                        });

                    return true;
                });
            return true;
        }
        bool                                                            establish(const boost::asio::yield_context& y, const std::function<void(connection*)>& established) noexcept;
        bool                                                            update(uint32_t now) noexcept
        {
            std::shared_ptr<Byte> packet;
            if (next_ == 0)
            {
            next:
                int32_t rnd = RandomNext(1, std::min<int>(AGGLIGATOR_INACTIVE_TIMEOUT >> 1, std::max<int>(AGGLIGATOR_CONNECT_TIMEOUT, AGGLIGATOR_RECONNECT_TIMEOUT) << 2));
                next_ = now + (uint32_t)rnd;
            }
            elif(now >= next_)
            {
                packet = make_shared_alloc<Byte>(2);
                if (!packet)
                {
                    return false;
                }

                Byte* memory = packet.get();
                memory[0] = 0;
                memory[1] = 0;

                if (sending_)
                {
                    next_packet_ = packet;
                    goto next;
                }
                elif(sent(packet, 2))
                {
                    if (sending_)
                    {
                        goto next;
                    }
                }

                return false;
            }

            return true;
        }

        std::shared_ptr<aggligator>                                     app_;
        convergence_ptr                                                 convergence_;
        client_ptr                                                      client_;
        std::shared_ptr<boost::asio::ip::tcp::socket>                   socket_;
        bool                                                            sending_;
        uint32_t                                                        next_;
        std::shared_ptr<Byte>                                           next_packet_;
#if defined(_WIN32)
        std::shared_ptr<QoSS>                                           qoss_;
#endif
        Byte                                                            buffer_[UINT16_MAX]; /* MAX:65507 */
    };

    static inline unsigned short ip_standard_chksum(void* dataptr, int len) noexcept
    {
        unsigned int acc;
        unsigned short src;
        unsigned char* octetptr;

        acc = 0;

        /* dataptr may be at odd or even addresses */
        octetptr = (unsigned char*)dataptr;
        while (len > 1)
        {
            /* declare first octet as most significant
               thus assume network order, ignoring host order */
            src = (unsigned short)((*octetptr) << 8);
            octetptr++;

            /* declare second octet as least significant */
            src |= (*octetptr);
            octetptr++;
            acc += src;
            len -= 2;
        }

        if (len > 0)
        {
            /* accumulate remaining octet */
            src = (unsigned short)((*octetptr) << 8);
            acc += src;
        }

        /* add deferred carry bits */
        acc = (unsigned int)((acc >> 16) + (acc & 0x0000ffffUL));
        if ((acc & 0xffff0000UL) != 0)
        {
            acc = (unsigned int)((acc >> 16) + (acc & 0x0000ffffUL));
        }

        /* This maybe a little confusing: reorder sum using htons()
           instead of ntohs() since it has a little less call overhead.
           The caller must invert bits for Internet sum ! */
        return ntohs((unsigned short)acc);
    }

    static inline unsigned short inet_chksum(void* dataptr, int len) noexcept
    {
        return (unsigned short)~ip_standard_chksum(dataptr, len);
    }

    aggligator::aggligator(boost::asio::io_context& context, const std::shared_ptr<Byte>& buffer, int buffer_size, int congestions) noexcept
        : context_(context)
        , buffer_(buffer)
        , buffer_size_(buffer_size)
        , congestions_(congestions)
        , server_mode_(false)
        , last_(0)
        , now_(GetTickCount())
        , rx_(0)
        , tx_(0)
        , rx_pps_(0)
        , tx_pps_(0)
    {
        if (NULL == buffer)
        {
            buffer_size = 0;
        }
        elif(buffer_size < 1)
        {
            buffer_ = NULL;
            buffer_size = 0;
        }
    }

    aggligator::~aggligator() noexcept
    {
        close();
    }

    void aggligator::close() noexcept
    {
        client_ptr client = std::move(client_);
        server_ptr server = std::move(server_);
        std::function<void()> exit = std::move(Exit);

        deadline_timer_cancel(reopen_);
        deadline_timer_cancel(timeout_);

        if (server)
        {
            server_.reset();
            server->close();
        }

        if (client)
        {
            client_.reset();
            client->close();
        }

        if (exit)
        {
            Exit = NULL;
            exit();
        }
    }

    void aggligator::update(uint64_t now) noexcept
    {
        uint32_t now_seconds = (uint32_t)(now / 1000);
        for (;;)
        {
            client_ptr pclient = client_;
            if (pclient && pclient->last_ != 0 && !pclient->update(now_seconds))
            {
                pclient->close();
            }

            break;
        }

        for (;;)
        {
            server_ptr pserver = server_;
            if (!pserver)
            {
                break;
            }

            list<client_ptr> releases;
            for (auto&& kv : pserver->clients_)
            {
                client_ptr& pclient = kv.second;
                if (pclient->last_ != 0 && !pclient->update(now_seconds))
                {
                    releases.emplace_back(pclient);
                }
            }

            for (client_ptr& pclient : releases)
            {
                pclient->close();
            }

            break;
        }
    }

    bool aggligator::create_timeout() noexcept
    {
        deadline_timer timeout_ptr = timeout_;
        if (timeout_ptr)
        {
            return true;
        }

        timeout_ptr = make_shared_object<boost::asio::deadline_timer>(context_);
        if (!timeout_ptr)
        {
            return false;
        }

        timeout_ = timeout_ptr;
        return nawait_timeout();
    }

    bool aggligator::nawait_timeout() noexcept
    {
        deadline_timer t = timeout_;
        if (t)
        {
            auto self = shared_from_this();
            t->expires_from_now(boost::posix_time::milliseconds(10));
            t->async_wait(
                [self, this](boost::system::error_code ec) noexcept
                {
                    if (ec == boost::system::errc::operation_canceled)
                    {
                        close();
                        return false;
                    }

                    uint64_t now = GetTickCount();
                    uint32_t now_seconds = (uint32_t)(now / 1000);

                    now_ = now;
                    if (last_ != now_seconds)
                    {
                        last_ = now_seconds;
                        update(now);

                        std::function<void(uint64_t)> tick = Tick;
                        if (tick)
                        {
                            tick(now);
                        }
                    }

                    return nawait_timeout();
                });
            return true;
        }

        return false;
    }

    void aggligator::deadline_timer_cancel(deadline_timer& t) noexcept
    {
        deadline_timer p = std::move(t);
        t.reset();

        boost::system::error_code ec;
        if (p)
        {
            p->cancel(ec);
        }
    }

    void aggligator::socket_flash_mode(bool value) noexcept
    {
        SOCKET_FLASH_MODE = value;
    }

    static bool socket_native_adjust(int fd) noexcept 
    {
        if (fd == -1) 
        {
            return false;
        }

        bool any = false;
        int tos = SOCKET_FLASH_MODE ? IPTOS_LOWDELAY : 0;

#if defined(_MACOS)
#if defined(IPV6_TCLASS)
        any |= ::setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, (char*)&tos, sizeof(tos)) == 0;
#endif
        any |= ::setsockopt(fd, IPPROTO_IP, IPV6_TCLASS, (char*)&tos, sizeof(tos)) == 0;
#else
#if defined(IPV6_TCLASS)
        any |= ::setsockopt(fd, SOL_IPV6, IPV6_TCLASS, (char*)&tos, sizeof(tos)) == 0;
#endif
        any |= ::setsockopt(fd, SOL_IP, IP_TOS, (char*)&tos, sizeof(tos)) == 0;
#endif
        return any;
    }

    static void socket_native_adjust(int sockfd, bool in4) noexcept
    {
        if (sockfd != -1)
        {
            uint8_t tos = SOCKET_FLASH_MODE ? IPTOS_LOWDELAY : 0;
            if (in4)
            {
#if defined(_MACOS)
                ::setsockopt(sockfd, IPPROTO_IP, IP_TOS, (char*)&tos, sizeof(tos));
#else
                ::setsockopt(sockfd, SOL_IP, IP_TOS, (char*)&tos, sizeof(tos));
#endif

#if defined(IP_DONTFRAGMENT)
                int dont_frag = IP_PMTUDISC_NOT_SET; // IP_PMTUDISC
                ::setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAGMENT, (char*)&dont_frag, sizeof(dont_frag));
#elif defined(IP_PMTUDISC_WANT)
                int dont_frag = IP_PMTUDISC_WANT;
                ::setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &dont_frag, sizeof(dont_frag));
#endif
            }
            else
            {
                // linux-user: Add missing IP_TOS, IPV6_TCLASS and IPV6_RECVTCLASS sockopts
                // QEMU:
                // https://patchwork.kernel.org/project/qemu-devel/patch/20170311195906.GA13187@ls3530.fritz.box/
#if defined(IPV6_TCLASS)
                ::setsockopt(sockfd, IPPROTO_IPV6, IPV6_TCLASS, (char*)&tos, sizeof(tos)); /* SOL_IPV6 */
#endif

#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_WANT)
                int dont_frag = IPV6_PMTUDISC_WANT;
                ::setsockopt(sockfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &dont_frag, sizeof(dont_frag));
#endif
            }

#if defined(SO_NOSIGPIPE)
            int no_sigpipe = 1;
            ::setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe));
#endif
        }
    }

    void aggligator::socket_adjust(int sockfd, bool in4) noexcept
    {
        socket_native_adjust(sockfd, in4);
        socket_native_adjust(sockfd);
    }

    void aggligator::socket_close(boost::asio::ip::udp::socket& socket) noexcept
    {
        if (socket.is_open())
        {
            boost::system::error_code ec;
            socket.cancel(ec);
            socket.close(ec);
        }
    }

    void aggligator::socket_close(boost::asio::ip::tcp::socket& socket) noexcept
    {
        if (socket.is_open())
        {
            boost::system::error_code ec;
            socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
            socket.cancel(ec);
            socket.close(ec);
        }
    }

    bool aggligator::server_accept(const acceptor& acceptor) noexcept
    {
        bool opened = acceptor->is_open();
        if (!opened)
        {
            close();
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> socket = make_shared_object<boost::asio::ip::tcp::socket>(context_);
        if (!socket)
        {
            close();
            return false;
        }

        auto self = shared_from_this();
        acceptor->async_accept(*socket, 
            [self, this, acceptor, socket](boost::system::error_code ec) noexcept
            {
                if (ec == boost::system::errc::operation_canceled)
                {
                    close();
                    return false;
                }
                elif(ec == boost::system::errc::success)
                {
                    boost::asio::spawn(context_,
                        [self, this, socket](const boost::asio::yield_context& y) noexcept
                        {
                            socket_adjust(*socket);
                            if (!(socket->is_open() && server_accept(socket, y)))
                            {
                                socket_close(*socket);
                            }
                        });
                }

                if (server_accept(acceptor))
                {
                    return true;
                }
                else
                {
                    close();
                    return false;
                }
            });
        return true;
    }

    bool aggligator::server_accept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::yield_context& y) noexcept
    {
        boost::system::error_code ec;
        server_ptr server = server_;
        if (!server)
        {
            return false;
        }

        deadline_timer timeout = make_shared_object<boost::asio::deadline_timer>(context_);
        if (!timeout)
        {
            return false;
        }
        else
        {
            timeout->expires_from_now(boost::posix_time::seconds(AGGLIGATOR_CONNECT_TIMEOUT));
            timeout->async_wait(
                [socket](boost::system::error_code ec) noexcept
                {
                    if (ec != boost::system::errc::operation_canceled)
                    {
                        socket_close(*socket);
                    }
                });
        }

        Byte data[128];
        uint16_t remote_port = 0;

        size_t bytes_transferred = boost::asio::async_read(*socket, boost::asio::buffer(data, 8), y[ec]);
        if (ec)
        {
            return false;
        }
        else
        {
            rx_ += 8;
            uint32_t m = *(uint32_t*)data;
            *(uint32_t*)(data + 4) ^= m;
            uint16_t* pchecksum = (uint16_t*)(data + 6);
            uint16_t checksum = *pchecksum;

            *pchecksum = 0;
            remote_port = ntohs(*(uint16_t*)(data + 4));

            uint16_t chksum = inet_chksum(data, 8);
            if (chksum != checksum)
            {
                return false;
            }
        }

        connection_ptr pconnection;
        client_ptr pclient;
        convergence_ptr pconvergence;
        unordered_map<int, client_ptr>& clients = server->clients_;

        std::shared_ptr<aggligator> my = shared_from_this();
        if (remote_port == 0)
        {
            pclient = make_shared_object<client>(my);
            if (!pclient)
            {
                return false;
            }

            pconvergence = make_shared_object<convergence>(my, pclient);
            if (!pconvergence)
            {
                return false;
            }

            boost::asio::ip::udp::socket& socket_dgram = pclient->socket_;
            socket_dgram.open(boost::asio::ip::udp::v6(), ec);

            if (ec)
            {
                return false;
            }
            else
            {
                socket_adjust(socket_dgram);
            }

            socket_dgram.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6::any(), 0), ec);
            if (ec)
            {
                return false;
            }

            boost::asio::ip::udp::endpoint local_endpoint = socket_dgram.local_endpoint(ec);
            if (ec)
            {
                return false;
            }

            remote_port = local_endpoint.port();
            pclient->server_mode_ = true;
            pclient->established_num_ = 1;
            pclient->connections_num_ = 1;
            pclient->remote_port_ = remote_port;
            pclient->convergence_ = pconvergence;

            pconnection = make_shared_object<connection>(my, pclient, pconvergence);
            if (!pconnection)
            {
                return false;
            }

            clients[remote_port] = pclient;
            pconnection->socket_ = socket;
            pclient->connections_.emplace_back(pconnection);

            if (!pclient->timeout())
            {
                return false;
            }
        }
        else
        {
            auto client_tail = clients.find(remote_port);
            auto client_endl = clients.end();
            if (client_tail == client_endl)
            {
                return false;
            }

            pclient = client_tail->second;
            if (!pclient)
            {
                clients.erase(client_tail);
                return false;
            }

            pconvergence = pclient->convergence_;
            if (!pconvergence)
            {
                return false;
            }

            pconnection = make_shared_object<connection>(my, pclient, pconvergence);
            if (!pconnection)
            {
                return false;
            }

            pconnection->socket_ = socket;
            pclient->established_num_++;
            pclient->connections_num_++;
            pclient->connections_.emplace_back(pconnection);
        }

#if defined(_WIN32)
        if (SOCKET_FLASH_MODE)
        {
            pconnection->qoss_ = connection::QoSS::New(socket->native_handle());
        }
#endif
        data[0] = (Byte)(remote_port >> 8);
        data[1] = (Byte)(remote_port);
        *(uint32_t*)(data + 2) = htonl(pconvergence->seq_no_);

        bytes_transferred = boost::asio::async_write(*socket, boost::asio::buffer(data, 6), y[ec]);
        if (ec)
        {
            return false;
        }
        else
        {
            tx_ += 6;
        }

        boost::asio::async_read(*socket, boost::asio::buffer(data, 8), y[ec]);
        if (ec)
        {
            return false;
        }

        rx_ += 8;
        if (*data != 0)
        {
            return false;
        }

        uint32_t connections_num = ntohl(*(uint32_t*)data);
        if (++pclient->handshakeds_num_ < connections_num)
        {
            return true;
        }
        
        uint32_t ack = ntohl(*(uint32_t*)(data + 4)) + 1;
        pconvergence->ack_no_ = ack;

        pclient->last_ = (uint32_t)(now() / 1000);
        for (connection_ptr& connection : pclient->connections_)
        {
            if (!connection->recv())
            {
                return false;
            }
        }

        deadline_timer_cancel(timeout);
        deadline_timer_cancel(pclient->timeout_);
        return pclient->loopback();
    }

    bool aggligator::server_open(const unordered_set<int>& bind_ports, const boost::asio::ip::address& destination_ip, int destination_port) noexcept
    {
        if (bind_ports.empty())
        {
            return false;
        }
        
        if (server_ || client_) 
        {
            return false;
        }

        server_ptr server = make_shared_object<aggligator::server>();
        if (NULL == server)
        {
            return false;
        }

        if (destination_port <= 0 || destination_port > UINT16_MAX)
        {
            return false;
        }

        if (ip_is_invalid(destination_ip))
        {
            return false;
        }

        bool any = false;
        for (int bind_port : bind_ports)
        {
            if (bind_port <= 0 || bind_port > UINT16_MAX)
            {
                continue;
            }
            else
            {
                auto tail = server->acceptors_.find(bind_port);
                auto endl = server->acceptors_.end();
                if (tail != endl)
                {
                    continue;
                }
            }

            auto acceptor = make_shared_object<boost::asio::ip::tcp::acceptor>(context_);
            if (NULL == acceptor)
            {
                break;
            }

            boost::system::error_code ec;
            acceptor->open(boost::asio::ip::tcp::v6(), ec);
            if (ec)
            {
                continue;
            }
            else
            {
                socket_adjust(*acceptor);
            }

            acceptor->bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6::any(), bind_port), ec);
            if (ec && bind_port != 0)
            {
                acceptor->bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6::any(), 0), ec);
                if (ec)
                {
                    continue;
                }
            }

            acceptor->listen(UINT16_MAX, ec);
            if (ec)
            {
                continue;
            }

            if (server_accept(acceptor))
            {
                any |= true;
                server->acceptors_[bind_port] = acceptor;
            }
        }

        server->server_endpoint_ = boost::asio::ip::udp::endpoint(destination_ip, destination_port);
        server->server_endpoint_ = ip_v4_to_v6(server->server_endpoint_);
        if (any)
        {
            server_ = server;
            server_mode_ = true;
        }

        return any && create_timeout();
    }

    bool aggligator::client_open(
        int                                                                 connections,
        int                                                                 bind_port,
        const unordered_set<boost::asio::ip::tcp::endpoint>&                servers) noexcept
    {
        if (servers.empty())
        {
            return false;
        }

        if (connections < 1)
        {
            connections = 1;
        }

        if (server_ || client_)
        {
            return false;
        }

        if (bind_port <= 0 || bind_port > UINT16_MAX)
        {
            return false;
        }

        unordered_set<boost::asio::ip::tcp::endpoint> connect_servers;
        for (const boost::asio::ip::tcp::endpoint& ep : servers)
        {
            int server_port = ep.port();
            if (server_port <= 0 || server_port > UINT16_MAX)
            {
                continue;
            }

            boost::asio::ip::address server_ip = ep.address();
            if (ip_is_invalid(server_ip))
            {
                continue;
            }

            connect_servers.emplace(ep);
        }

        if (connect_servers.empty())
        {
            return false;
        }

        client_ptr pclient = make_shared_object<client>(shared_from_this());
        if (!pclient)
        {
            return false;
        }

        client_ = pclient;
        server_mode_ = false;
        return create_timeout() && pclient->open(connections, bind_port, connect_servers);
    }

#if defined(JEMALLOC)
    void aggligator::jemaillc_areans_set_default() noexcept
    {
        size_t dirty_decay_ms = 0;
        size_t muzzy_decay_ms = 0;

        je_mallctl("arenas.dirty_decay_ms", NULL, 0, reinterpret_cast<void*>(&dirty_decay_ms), sizeof(dirty_decay_ms));
        je_mallctl("arenas.muzzy_decay_ms", NULL, 0, reinterpret_cast<void*>(&muzzy_decay_ms), sizeof(muzzy_decay_ms));
    }
#endif

    bool aggligator::ip_is_invalid(const boost::asio::ip::address& address) noexcept
    {
        if (address.is_v4())
        {
            boost::asio::ip::address_v4 in = address.to_v4();
            if (in.is_multicast() || in.is_unspecified())
            {
                return true;
            }

            uint32_t ip = htonl(in.to_uint());
            return ip == INADDR_ANY || ip == INADDR_NONE;
        }
        elif(address.is_v6())
        {
            boost::asio::ip::address_v6 in = address.to_v6();
            if (in.is_multicast() || in.is_unspecified())
            {
                return true;
            }

            return false;
        }
        else
        {
            return true;
        }
    }

    bool aggligator::server_closed(client* client) noexcept
    {
        if (client->server_mode_)
        {
            server_ptr server = server_;
            if (server)
            {
                auto& clients = server->clients_;
                auto tail = clients.find(client->remote_port_);
                auto endl = clients.end();
                if (tail != endl)
                {
                    client_ptr p = std::move(tail->second);
                    clients.erase(tail);

                    if (p)
                    {
                        p->close();
                    }
                }
            }
        }

        return false;
    }

    bool aggligator::client_reopen(client* client) noexcept
    {
        if (client->server_mode_ || client != client_.get())
        {
            return false;
        }

        client_ptr pclient = std::move(client_);
        client_.reset();

        if (pclient)
        {
            pclient->close();
        }
        else
        {
            close();
            return false;
        }

        deadline_timer t = make_shared_object<boost::asio::deadline_timer>(context_);
        if (!t)
        {
            close();
            return false;
        }

        unordered_set<boost::asio::ip::tcp::endpoint> servers = pclient->server_endpoints_;
        uint32_t connections = pclient->connections_num_ / servers.size();
        int bind_port = pclient->local_port_;

        auto self = shared_from_this();
        t->expires_from_now(boost::posix_time::seconds(AGGLIGATOR_RECONNECT_TIMEOUT));
        t->async_wait(
            [self, this, connections, bind_port, servers](boost::system::error_code ec) noexcept
            {
                deadline_timer_cancel(reopen_);
                if (ec == boost::system::errc::operation_canceled)
                {
                    close();
                    return false;
                }
                elif(ec)
                {
                    close();
                    return false;
                }

                bool opened = client_open(connections, bind_port, servers);
                if (!opened)
                {
                    close();
                    return false;
                }

                return true;
            });

        reopen_ = t;
        return true;
    }

    std::shared_ptr<Byte> aggligator::make_shared_bytes(int length) noexcept
    {
        return length > 0 ? make_shared_alloc<Byte>(length) : NULL;
    }

    bool aggligator::client::update(uint32_t now_seconds) noexcept
    {
        if (now_seconds >= (last_ + AGGLIGATOR_INACTIVE_TIMEOUT))
        {
            return false;
        }

        std::shared_ptr<aggligator> aggligator = app_;
        if (!aggligator)
        {
            return false;
        }

        std::shared_ptr<convergence> pconvergence = convergence_;
        if (!pconvergence)
        {
            return false;
        }

        if (pconvergence->rq_congestions_ > aggligator->congestions_)
        {
            return false;
        }

        for (connection_ptr& connection : connections_)
        {
            if (!connection->update(now_seconds))
            {
                return false;
            }
        }

        return true;
    }

    void aggligator::client::close() noexcept
    {
        std::shared_ptr<aggligator> aggligator = std::move(app_);
        app_.reset();

        convergence_ptr convergence = std::move(convergence_);
        convergence_.reset();

        if (convergence)
        {
            convergence->close();
        }

        list<connection_ptr> connections = std::move(connections_);
        connections_.clear();

        for (connection_ptr& connection : connections)
        {
            connection->close();
        }

        deadline_timer_cancel(timeout_);
        aggligator::socket_close(socket_);

        if (aggligator)
        {
            aggligator->server_closed(this);
            aggligator->client_reopen(this);
        }
    }

    bool aggligator::client::send(Byte* packet, int packet_length) noexcept
    {
        if (NULL == packet || packet_length < 1)
        {
            return false;
        }

        convergence_ptr convergence = convergence_;
        if (NULL == convergence)
        {
            return false;
        }

        auto tail = connections_.begin();
        auto endl = connections_.end();
        if (tail == endl)
        {
            return false;
        }

        int message_length;
        uint32_t seq = ++convergence->seq_no_;

        std::shared_ptr<Byte> message = convergence::pack(packet, packet_length, seq, message_length);
        if (NULL == message || message_length < 1)
        {
            return false;
        }

        queue<send_packet>& send_queue = convergence->send_queue_;
        send_queue.emplace_back(send_packet{ message, message_length });

        for (;;)
        {
            auto sqt = send_queue.begin();
            if (sqt == send_queue.end())
            {
                return true;
            }

            connection_ptr connection;
            for (; tail != endl; tail++)
            {
                connection_ptr& i = *tail;
                if (!i->sending_)
                {
                    connection = i;
                    break;
                }
            }

            if (connection)
            {
                send_packet messages = *sqt;
                send_queue.erase(sqt);

                bool ok = connection->sent(messages.packet, messages.length);
                if (ok)
                {
                    if (connection->sending_ && connections_num_ > 1)
                    {
                        connections_.erase(tail);
                        connections_.emplace_back(connection);
                    }

                    return true;
                }

                return false;
            }
            else
            {
                return true;
            }
        }
    }

    bool aggligator::client::timeout() noexcept
    {
        ptr aggligator = app_;
        if (!aggligator)
        {
            close();
            return false;
        }

        deadline_timer timeout = make_shared_object<boost::asio::deadline_timer>(aggligator->context_);
        if (!timeout)
        {
            close();
            return false;
        }

        auto self = shared_from_this();
        timeout->expires_from_now(boost::posix_time::seconds(AGGLIGATOR_CONNECT_TIMEOUT));
        timeout->async_wait(
            [self, this](boost::system::error_code ec) noexcept
            {
                if (ec == boost::system::errc::operation_canceled)
                {
                    return false;
                }
                else
                {
                    close();
                    return true;
                }
            });

        timeout_ = timeout;
        return true;
    }

    bool aggligator::client::loopback() noexcept
    {
        ptr aggligator = app_;
        if (!aggligator)
        {
            close();
            return false;
        }

        std::shared_ptr<Byte> buffer = aggligator->buffer_;
        if (!buffer)
        {
            close();
            return false;
        }

        boost::system::error_code ec;
        if (!socket_.is_open())
        {
            socket_.open(boost::asio::ip::udp::v6(), ec);
            if (ec)
            {
                close();
                return false;
            }
            else
            {
                socket_adjust(socket_);
            }

            socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6::any(), local_port_), ec);
            if (ec)
            {
                close();
                return false;
            }
        }

        auto self = shared_from_this();
        socket_.async_receive_from(boost::asio::buffer(buffer.get(), aggligator->buffer_size_), source_endpoint_,
            [self, this](boost::system::error_code ec, std::size_t sz) noexcept
            {
                ptr aggligator = app_;
                if (!aggligator)
                {
                    close();
                    return false;
                }

                int bytes_transferred = static_cast<int>(sz);
                if (bytes_transferred > 0 && ec == boost::system::errc::success)
                {
                    std::shared_ptr<Byte> buffer = aggligator->buffer_;
                    if (!buffer)
                    {
                        close();
                        return false;
                    }

                    bool bok = send(buffer.get(), bytes_transferred);
                    if (!bok)
                    {
                        close();
                        return false;
                    }
                }

                return loopback();
            });
        return true;
    }

    bool aggligator::client::open(int connections, int bind_port, unordered_set<boost::asio::ip::tcp::endpoint>& servers) noexcept
    {
        using tcp_endpoint_list = list<boost::asio::ip::tcp::endpoint>;

        std::shared_ptr<aggligator> aggligator = app_;
        if (NULL == aggligator)
        {
            return false;
        }

        std::shared_ptr<tcp_endpoint_list> list = make_shared_object<tcp_endpoint_list>();
        if (NULL == list)
        {
            return false;
        }

        client_ptr self = shared_from_this();
        convergence_ptr pconvergence = make_shared_object<convergence>(aggligator, self);
        if (NULL == pconvergence)
        {
            return false;
        }

        convergence_ = pconvergence;
        server_mode_ = false;
        local_port_ = bind_port;
        server_endpoints_ = servers;

        auto connect_to_server = 
            [self, this, aggligator, pconvergence](const boost::asio::ip::tcp::endpoint& server, const std::function<void(connection*)>& established) noexcept
            {
                connection_ptr pconnection = make_shared_object<connection>(aggligator, self, pconvergence);
                if (!pconnection)
                {
                    return false;
                }

                bool ok = pconnection->open(server, established);
                if (!ok)
                {
                    return false;
                }

                connections_.emplace_back(pconnection);
                return true;
            };

        for (int i = 0; i < connections; i++)
        {
            for (const boost::asio::ip::tcp::endpoint& server : servers)
            {
                connections_num_++;
                list->emplace_back(server);
            }
        }

        boost::asio::ip::tcp::endpoint master_node = list->front();
        list->pop_front();
        if (list->begin() == list->end())
        {
            list.reset();
        }

        return timeout() && connect_to_server(master_node,
            [this, list, connect_to_server](connection* connection) noexcept
            {
                if (NULL == list)
                {
                    return false;
                }

                bool any = false;
                for (const boost::asio::ip::tcp::endpoint& server : *list)
                {
                    any |= connect_to_server(server, NULL);
                }

                return any;
            });
    }

    std::shared_ptr<Byte> aggligator::convergence::pack(Byte* packet, int packet_length, uint32_t seq, int& out) noexcept
    {
        out = 0;
        if (NULL == packet || packet_length < 1)
        {
            return NULL;
        }

        int message_length = 4 + packet_length;
        int final_length = 2 + message_length;

        std::shared_ptr<Byte> message = make_shared_alloc<Byte>(final_length);
        if (NULL == message)
        {
            return NULL;
        }

        Byte* stream = message.get();
        *stream++ = (Byte)(message_length >> 8);
        *stream++ = (Byte)(message_length);

        *stream++ = (Byte)(seq >> 24);
        *stream++ = (Byte)(seq >> 16);
        *stream++ = (Byte)(seq >> 8);
        *stream++ = (Byte)(seq);

        out = final_length;
        memcpy(stream, packet, packet_length);
        return message;
    }

    bool aggligator::convergence::input(Byte* packet, int packet_length) noexcept
    {
        if (NULL == packet || packet_length < 4)
        {
            return false;
        }

        std::shared_ptr<aggligator> aggligator = app_;
        if (NULL == aggligator)
        {
            return false;
        }

        uint32_t seq = htonl(*(uint32_t*)packet);
        packet += 4;
        packet_length -= 4;

        int max_congestions = aggligator->congestions_;
        if (max_congestions < 1)
        {
            return process(packet, packet_length, true);
        }
        else
        {
            if (seq < ack_no_)
            {
                wraparound_ = before(ack_no_, seq);
                if (!wraparound_)
                {
                    return true;
                }
            }

            if (++rq_congestions_ > max_congestions)
            {
                return false;
            }
        }

        if (ack_no_ == seq)
        {
            if (!process(packet, packet_length, false))
            {
                return false;
            }

            auto tail = recv_queue_.begin();
            auto endl = recv_queue_.end();
            while (tail != endl)
            {
                if (ack_no_ != tail->seq)
                {
                    break;
                }
                else
                {
                    recv_packet& pr = *tail;
                    if (!process(pr.packet.get(), pr.length, false))
                    {
                        return false;
                    }
                }

                tail = recv_queue_.erase(tail);
            }

            return true;
        }

        recv_packet r;
        r.seq = seq;
        r.length = packet_length;
        r.packet = aggligator->make_shared_bytes(packet_length);
        if (r.packet)
        {
            memcpy(r.packet.get(), packet, packet_length);
            if (wraparound_)
            {
                emplace_wraparound(recv_queue_, r);
            }
            else
            {
                emplace(recv_queue_, r);
            }

            return true;
        }
        else
        {
            return false;
        }
    }

    void aggligator::convergence::close() noexcept
    {
        std::shared_ptr<client> client = std::move(client_);
        client_.reset();

        std::shared_ptr<aggligator> aggligator = std::move(app_);
        app_.reset();

        send_queue_.clear();
        recv_queue_.clear();

        if (client)
        {
            client->close();
        }
    }

    bool aggligator::convergence::output(Byte* packet, int packet_length) noexcept
    {
        std::shared_ptr<aggligator> aggligator = app_;
        if (!aggligator)
        {
            return false;
        }

        std::shared_ptr<client> client = client_;
        if (!client)
        {
            return false;
        }

        boost::asio::ip::udp::socket& socket = client->socket_;
        if (!socket.is_open())
        {
            return false;
        }

        boost::system::error_code ec;
        if (client->server_mode_)
        {
            server_ptr server = aggligator->server_;
            if (!server)
            {
                return false;
            }

            socket.send_to(boost::asio::buffer(packet, packet_length), server->server_endpoint_, boost::asio::socket_base::message_end_of_record, ec);
        }
        else
        {
            socket.send_to(boost::asio::buffer(packet, packet_length), client->source_endpoint_, boost::asio::socket_base::message_end_of_record, ec);
        }

        return true;
    }

    template <typename T>
    static bool aggligator_socket_adjust(T& socket) noexcept
    {
        boost::system::error_code ec;
        if (!socket.is_open())
        {
            return false;
        }

        int sockfd = socket.native_handle();
        if (sockfd == -1)
        {
            return false;
        }

        auto ep = socket.local_endpoint(ec);
        if (ec)
        {
            aggligator::socket_adjust(sockfd, true);
        }
        else
        {
            boost::asio::ip::address ip = ep.address();
            aggligator::socket_adjust(sockfd, ip.is_v4());
        }

        return true;
    }

    template <typename T>
    static bool aggligator_tcp_socket_adjust(T& socket) noexcept
    {
        if (aggligator_socket_adjust(socket))
        {
            boost::system::error_code ec;
            socket.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
            socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
            socket.set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(true), ec);
            return true;
        }

        return false;
    }

    bool aggligator::socket_adjust(boost::asio::ip::udp::socket& socket) noexcept
    {
        if (aggligator_socket_adjust(socket))
        {
            boost::system::error_code ec;
            socket.set_option(boost::asio::ip::udp::socket::reuse_address(true), ec);
            return true;
        }

        return false;
    }

    bool aggligator::socket_adjust(boost::asio::ip::tcp::socket& socket) noexcept
    {
        return aggligator_tcp_socket_adjust(socket);
    }

    bool aggligator::socket_adjust(boost::asio::ip::tcp::acceptor& socket) noexcept
    {
        return aggligator_tcp_socket_adjust(socket);
    }

    aggligator::link_status aggligator::status(information& i) noexcept
    {
        if (server_mode())
        {
            return link_status_none;
        }

        if (i.bind_ports.empty())
        {
            return i.client_count > 0 ? link_status_connecting : link_status_reconnecting;
        }

        if (i.establish_count < i.connection_count)
        {
            return link_status_connecting;
        }
        else
        {
            return link_status_established;
        }
    }

    aggligator::link_status aggligator::status() noexcept
    {
        information i;
        if (info(i))
        {
            return status(i);
        }

        return link_status_unknown;
    }

    bool aggligator::info(information& i) noexcept
    {
        i.server_endpoints.clear();
        i.bind_ports.clear();
        i.client_count = 0;
        i.connection_count = 0;
        i.establish_count = 0;
        i.rx = rx_;
        i.tx = tx_;
        i.rx_pps = rx_pps_;
        i.tx_pps = tx_pps_;

        server_ptr server = server_;
        client_ptr client = client_;
        if (server)
        {
            i.client_count = server->clients_.size();
            for (auto&& kv : server->acceptors_)
            {
                i.bind_ports.emplace(kv.first);
            }

            for (auto&& kv : server->clients_)
            {
                client_ptr& pclient = kv.second;
                i.establish_count += pclient->established_num_;
                i.connection_count += pclient->connections_num_;
            }
        }
        elif(client)
        {
            boost::asio::ip::udp::socket& dgram_socket = client->socket_;
            if (dgram_socket.is_open())
            {
                i.bind_ports.emplace(client->local_port_);
            }

            i.client_count = 1;
            i.connection_count = client->connections_num_;
            i.establish_count = client->established_num_;
            i.server_endpoints = client->server_endpoints_;
        }
        
        return true;
    }

    boost::asio::ip::udp::endpoint aggligator::ip_v6_to_v4(const boost::asio::ip::udp::endpoint& ep) noexcept
    {
        boost::asio::ip::address host = ep.address();
        if (host.is_v4())
        {
            return ep;
        }
        elif(host.is_v6())
        {
            boost::asio::ip::address_v6 in6 = host.to_v6();
            boost::asio::ip::address_v6::bytes_type bytes = in6.to_bytes();

#pragma pack(push, 1)
            struct IPV62V4ADDR 
            {
                uint64_t R1;
                uint16_t R2;
                uint16_t R3;
                uint32_t R4;
            };
#pragma pack(pop)

            IPV62V4ADDR* in = (IPV62V4ADDR*)bytes.data();
            if (in->R1 || in->R2 || in->R3 != UINT16_MAX) 
            {
                return ep;
            }

            boost::asio::ip::address_v4 r4(ntohl(in->R4));
            return boost::asio::ip::udp::endpoint(r4, ep.port());
        }
        else
        {
            return boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), 0);
        }
    }

    boost::asio::ip::udp::endpoint aggligator::ip_v4_to_v6(const boost::asio::ip::udp::endpoint& ep) noexcept
    {
        boost::asio::ip::address host = ep.address();
        if (host.is_v4())
        {
#pragma pack(push, 1)
            struct IPV62V4ADDR
            {
                uint64_t R1;
                uint16_t R2;
                uint16_t R3;
                uint32_t R4;
            };
#pragma pack(pop)

            boost::asio::ip::address_v4 in4 = host.to_v4();
            boost::asio::ip::address_v4::bytes_type bytes = in4.to_bytes();

            IPV62V4ADDR in;
            in.R1 = 0;
            in.R2 = 0;
            in.R3 = UINT16_MAX;
            in.R4 = *(uint32_t*)bytes.data();

            boost::asio::ip::address_v6 in6(*(boost::asio::ip::address_v6::bytes_type*)&in);
            return boost::asio::ip::udp::endpoint(in6, ep.port());
        }
        elif(host.is_v6())
        {
            return ep;
        }
        else
        {
            return boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6::any(), 0);
        }
    }

    boost::asio::ip::tcp::endpoint aggligator::ip_v6_to_v4(const boost::asio::ip::tcp::endpoint& ep) noexcept
    {
        auto r = ip_v6_to_v4(boost::asio::ip::udp::endpoint(ep.address(), ep.port()));
        return boost::asio::ip::tcp::endpoint(r.address(), r.port());
    }

    boost::asio::ip::tcp::endpoint aggligator::ip_v4_to_v6(const boost::asio::ip::tcp::endpoint& ep) noexcept
    {
        auto r = ip_v4_to_v6(boost::asio::ip::udp::endpoint(ep.address(), ep.port()));
        return boost::asio::ip::tcp::endpoint(r.address(), r.port());
    }

    bool aggligator::connection::establish(const boost::asio::yield_context& y, const std::function<void(connection*)>& established) noexcept
    {
        std::shared_ptr<aggligator> aggligator = app_;
        if (!aggligator)
        {
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
        if (!socket)
        {
            return false;
        }

        if (!socket->is_open())
        {
            return false;
        }

        std::shared_ptr<client> client = aggligator->client_;
        if (!client)
        {
            return false;
        }

        Byte data[128];
        std::shared_ptr<convergence> convergence = client->convergence_;
        if (!convergence)
        {
            return false;
        }
        else
        {
            Byte* p = data;
            uint32_t m = (uint32_t)RandomNext(1, INT32_MAX);
            *(uint32_t*)p = m;
            p += 4;

            uint16_t remote_port = 0;
            if (client->established_num_ != 0)
            {
                remote_port = client->remote_port_;
            }

            *(uint16_t*)p = htons(remote_port);
            p += 2;

            *(uint16_t*)p = 0;
            *(uint16_t*)p = inet_chksum(data, 8);
            *(uint32_t*)(data + 4) ^= m;
        }

        boost::system::error_code ec;
        boost::asio::async_write(*socket, boost::asio::buffer(data, 8), y[ec]);
        if (ec)
        {
            return false;
        }
        else
        {
            aggligator->tx_ += 8;
        }

        boost::asio::async_read(*socket, boost::asio::buffer(data, 6), y[ec]);
        if (ec)
        {
            return false;
        }
        else
        {
            aggligator->rx_ += 6;
        }

        uint16_t remote_port = (uint16_t)(data[0] << 8 | data[1]);
        if (remote_port < 1)
        {
            return false;
        }

        uint32_t ack = ntohl(*(uint32_t*)(data + 2)) + 1;
        if (client->established_num_ == 0)
        {
            convergence->ack_no_ = ack;
        }
        elif(convergence->ack_no_ != ack)
        {
            return false;
        }

        client->remote_port_ = remote_port;
        client->established_num_++;
        if (established)
        {
            established(this);
        }

        if (client->established_num_ < client->connections_num_)
        {
            return true;
        }

        *(uint32_t*)data = htonl(client->connections_num_);
        *(uint32_t*)(data + 4) = htonl(convergence->seq_no_);

        for (connection_ptr& connection : client->connections_)
        {
            std::shared_ptr<boost::asio::ip::tcp::socket> connection_socket = connection->socket_;
            if (NULL == connection_socket)
            {
                return false;
            }

            if (!connection_socket->is_open())
            {
                return false;
            }

            boost::asio::async_write(*connection_socket, boost::asio::buffer(data, 8), y[ec]);
            if (ec)
            {
                return false;
            }

            aggligator->tx_ += 8;
        }

        client->last_ = (uint32_t)(aggligator->now() / 1000);
        for (connection_ptr& connection : client->connections_)
        {
            if (!connection->recv())
            {
                return false;
            }
        }

        deadline_timer_cancel(client->timeout_);
        return client->loopback();
    }

    bool FileWriteAllBytes(const char* path, const void* data, int length) noexcept 
    {
        if (NULL == path || length < 0) 
        {
            return false;
        }

        if (NULL == data && length != 0) 
        {
            return false;
        }

        FILE* f = fopen(path, "wb+");
        if (NULL == f) 
        {
            return false;
        }

        if (length > 0) 
        {
            fwrite((char*)data, length, 1, f);
        }

        fflush(f);
        fclose(f);
        return true;
    }

    void SetThreadPriorityToMaxLevel() noexcept 
    {
#if defined(_WIN32)
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
#else
        /* ps -eo state,uid,pid,ppid,rtprio,time,comm */
        struct sched_param param_;
        param_.sched_priority = sched_get_priority_max(SCHED_FIFO); /* SCHED_RR */
        pthread_setschedparam(pthread_self(), SCHED_FIFO, &param_); /* pthread_getthreadid_np() */
#endif
    }

    void SetProcessPriorityToMaxLevel() noexcept
    {
#if defined(_WIN32)
        SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
#else
#if defined(_LINUX)
        char path_[PATH_MAX];
        snprintf(path_, sizeof(path_), "/proc/%d/oom_adj", getpid());

        char level_[] = "-17";
        FileWriteAllBytes(path_, level_, sizeof(level_));
#endif

        /* Processo pai deve ter prioridade maior que os filhos. */
        setpriority(PRIO_PROCESS, getpid(), -20);

#if defined(_LINUX)
        /* ps -eo state,uid,pid,ppid,rtprio,time,comm */
        struct sched_param param_;
        param_.sched_priority = sched_get_priority_max(SCHED_FIFO); // SCHED_RR

        if (sched_setscheduler(getpid(), SCHED_RR, &param_) < 0) {
            sched_setscheduler(getpid(), SCHED_FIFO, &param_);
        }
#endif
#endif
    }

    // On the Android platform, call: boost::asio::ip::address::from_string function will lead to collapse, 
    // Only is to compile the Release code and opened the compiler code optimization.
    boost::asio::ip::address StringToAddress(const char* s, boost::system::error_code& ec) noexcept 
    {
        ec = boost::asio::error::invalid_argument;
        if (NULL == s || *s == '\x0') 
        {
            return boost::asio::ip::address_v4::any();
        }

        struct in_addr addr4;
        struct in6_addr addr6;
        if (inet_pton(AF_INET6, s, &addr6) > 0) 
        {
            boost::asio::ip::address_v6::bytes_type bytes;
            memcpy(bytes.data(), addr6.s6_addr, bytes.size());

            ec.clear();
            return boost::asio::ip::address_v6(bytes);
        }
        else if (inet_pton(AF_INET, s, &addr4) > 0) 
        {
            ec.clear();
            return boost::asio::ip::address_v4(htonl(addr4.s_addr));
        }
        else 
        {
            return boost::asio::ip::address_v4::any();
        }
    }

    int RandomNext(volatile unsigned int* seed) noexcept
    {
        unsigned int next = *seed;
        int result;

        next *= 1103515245;
        next += 12345;
        result = (unsigned int)(next / 65536) % 2048;

        next *= 1103515245;
        next += 12345;
        result <<= 10;
        result ^= (unsigned int)(next / 65536) % 1024;

        next *= 1103515245;
        next += 12345;
        result <<= 10;
        result ^= (unsigned int)(next / 65536) % 1024;

        *seed = next;
        return result;
    }

    int RandomNext(int min, int max) noexcept 
    {
        static volatile unsigned int seed = (unsigned int)(GetTickCount() / 1000);

        int v = RandomNext(&seed);
        return v % (max - min + 1) + min;
    }

    uint64_t GetTickCount(bool microseconds) noexcept 
    {
        auto now = std::chrono::high_resolution_clock::now();
        uint64_t tick = 0;
        if (microseconds) 
        {
            tick = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
        }
        else 
        {
            tick = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
        }
        return tick;
    }

    std::string GetFullExecutionFilePath() noexcept
    {
#if defined(_WIN32)
        char exe[8096]; /* MAX_PATH */
        GetModuleFileNameA(NULL, exe, sizeof(exe));
        return exe;
#elif defined(_MACOS)
        char path[PATH_MAX];
        uint32_t size = sizeof(path);
        if (_NSGetExecutablePath(path, &size) == 0)
        {
            return path;
        }

#if defined(PROC_PIDPATHINFO_MAXSIZE)
        char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
        proc_pidpath(getpid(), pathbuf, sizeof(pathbuf));
        return pathbuf;
#else
        return "";
#endif
#else
        char sz[PATH_MAX + 1];
        int dw = readlink("/proc/self/exe", sz, PATH_MAX);
        sz[dw] = '\x0';
        return dw < 1 ? "" : sz;
#endif
    }

    std::string GetCurrentDirectoryPath() noexcept
    {
#if defined(_WIN32)
        char cwd[8096];
        ::GetCurrentDirectoryA(sizeof(cwd), cwd);
        return cwd;
#else
        char sz[PATH_MAX + 1];
        return ::getcwd(sz, PATH_MAX);
#endif
    }

    std::string GetApplicationStartupPath() noexcept
    {
        std::string exe = GetFullExecutionFilePath();
#if defined(_WIN32)
        std::size_t pos = exe.rfind('\\');
#else
        std::size_t pos = exe.rfind('/');
#endif
        if (pos == std::string::npos)
        {
            return exe;
        }
        else
        {
            return exe.substr(0, pos);
        }
    }

    std::string GetExecutionFileName() noexcept
    {
        std::string exe = GetFullExecutionFilePath();
#if defined(_WIN32)
        std::size_t pos = exe.rfind('\\');
#else
        std::size_t pos = exe.rfind('/');
#endif
        if (pos == std::string::npos)
        {
            return exe;
        }
        else
        {
            return exe.substr(pos + 1);
        }
    }

    int GetCurrentProcessId() noexcept
    {
#if defined(_WIN32) || defined(_WIN64)
        return ::GetCurrentProcessId();
#else
        return ::getpid();
#endif
    }

    std::string StrFormatByteSize(int64_t size) noexcept 
    {
        static const char* aszByteUnitsNames[] = { "B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB", "DB", "NB" };

        long double d = (long double)llabs(size);
        unsigned int i = 0;
        while (i < 10 && d > 1024) 
        {
            d /= 1024;
            i++;
        }

        char sz[1000 + 1];
        snprintf(sz, 1000, "%Lf %s", d, aszByteUnitsNames[i]);
        return sz;
    }

    bool SetConsoleCursorPosition(int x, int y) noexcept 
    {
#if defined(_WIN32)
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (NULL == hConsole) 
        {
            return false;
        }

        COORD coord = { (SHORT)x, (SHORT)y };
        return ::SetConsoleCursorPosition(hConsole, coord);
#else
        return ::fprintf(stdout, "\033[%d;%dH", x, y) > 0;
#endif
    }

    bool GetConsoleWindowSize(int& x, int& y) noexcept 
    {
        x = 0;
        y = 0;

#if defined(_WIN32)
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (NULL == hConsole) 
        {
            return false;
        }

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (!::GetConsoleScreenBufferInfo(hConsole, &csbi)) 
        {
            return false;
        }

        y = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        x = csbi.srWindow.Right - csbi.srWindow.Left + 1;
#else
        struct winsize w;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1) 
        {
            return false;
        }

        x = w.ws_col;
        y = w.ws_row;
#endif
        return true;
    }

    bool ClearConsoleOutputCharacter() noexcept 
    {
#if defined(_WIN32)
        HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (NULL != hStdOut) 
        {
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            if (GetConsoleScreenBufferInfo(hStdOut, &csbi)) 
            {
                DWORD consoleSize = csbi.dwSize.X * csbi.dwSize.Y;
                DWORD charsWritten;

                FillConsoleOutputCharacter(hStdOut, ' ', consoleSize, { 0, 0 }, &charsWritten);
                FillConsoleOutputAttribute(hStdOut, csbi.wAttributes, consoleSize, { 0, 0 }, &charsWritten);

                if (::SetConsoleCursorPosition(hStdOut, { 0, 0 })) 
                {
                    return true;
                }
            }
        }

        return system("cls") == 0;
#else
        return system("clear") == 0;
#endif
    }

    bool HideConsoleCursor(bool value) noexcept 
    {
#if defined(_WIN32)
        HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
        if (NULL != consoleHandle) 
        {
            CONSOLE_CURSOR_INFO cursorInfo;
            if (GetConsoleCursorInfo(consoleHandle, &cursorInfo)) 
            {
                cursorInfo.bVisible = !value;
                if (SetConsoleCursorInfo(consoleHandle, &cursorInfo)) 
                {
                    return true;
                }
            }
        }

        return false;
#else
        if (value) 
        {
            fprintf(stdout, "\033[?25l");
        }
        else 
        {
            fprintf(stdout, "\033[?25h");
        }
        return true;
#endif
    }

    bool AddShutdownApplicationEventHandler(std::function<bool()> e) noexcept
    {
        static std::function<bool()> eeh = NULL;

        auto SIG_EEH =
            [](int signo) noexcept -> void
            {
                std::function<bool()> e = std::move(eeh);
                if (NULL != e)
                {
                    eeh = NULL;
                    e();
                }
                else
                {
                    signal(signo, SIG_DFL);
                    raise(signo);
                }
            };

        typedef void (*__sa_handler_unix__) (int); /* __sighandler_t */

        __sa_handler_unix__ SIG_IGN_V = SIG_IGN;
        __sa_handler_unix__ SIG_EEH_V = SIG_EEH;

        if (NULL != e)
        {
            eeh = e;
        }
        else
        {
            eeh = NULL;
            SIG_EEH_V = SIG_DFL;
            SIG_IGN_V = SIG_DFL;
        }

        /* retrieve old and set new handlers */
        /* restore prevouis signal actions   */
#ifdef _ANDROID
        signal(35, SIG_IGN_V); // FDSCAN(SI_QUEUE)
#endif

#ifdef SIGPIPE
        signal(SIGPIPE, SIG_IGN_V);
#endif

#ifdef SIGHUP
        signal(SIGHUP, SIG_IGN_V);
#endif

#ifdef SIGINT
        signal(SIGINT, SIG_EEH_V);
#endif

#ifdef SIGTERM
        signal(SIGTERM, SIG_EEH_V);
#endif

#ifdef SIGSYS
        signal(SIGSYS, SIG_EEH_V);
#endif

#ifdef SIGIOT
        signal(SIGIOT, SIG_EEH_V);
#endif

#ifdef SIGUSR1
        signal(SIGUSR1, SIG_EEH_V);
#endif

#ifdef SIGUSR2
        signal(SIGUSR2, SIG_EEH_V);
#endif

#ifdef SIGXCPU
        signal(SIGXCPU, SIG_EEH_V);
#endif

#ifdef SIGXFSZ
        signal(SIGXFSZ, SIG_EEH_V);
#endif

#ifdef SIGTRAP
        signal(SIGTRAP, SIG_EEH_V); 
#endif

#ifdef SIGBUS
        signal(SIGBUS, SIG_EEH_V); 
#endif

#ifdef SIGQUIT
        signal(SIGQUIT, SIG_EEH_V);   
#endif

        /* Some specific cpu architecture platforms do not support this signal macro, */
        /* Such as mips and mips64 instruction set cpu architecture platforms.        */
#ifdef SIGSTKFLT
        signal(SIGSTKFLT, SIG_EEH_V); 
#endif

#ifdef SIGSEGV
        signal(SIGSEGV, SIG_EEH_V);  
#endif

#ifdef SIGFPE
        signal(SIGFPE, SIG_EEH_V);    
#endif

#ifdef SIGABRT
        signal(SIGABRT, SIG_EEH_V);  
#endif

#ifdef SIGILL
        signal(SIGILL, SIG_EEH_V);   
#endif
        return true;
    }

    bool ToBoolean(const char* s) noexcept
    {
        if (NULL == s || *s == '\x0')
        {
            return false;
        }

        char ch = s[0];
        if (ch == '0' || ch == ' ')
        {
            return false;
        }

        if (ch == 'f' || ch == 'F')
        {
            return false;
        }

        if (ch == 'n' || ch == 'N')
        {
            return false;
        }

        if (ch == 'c' || ch == 'C')
        {
            return false;
        }

        return true;
    }

    bool GetCommandArgument(const char* name, int argc, const char** argv, bool defaultValue) noexcept 
    {
        std::string str = GetCommandArgument(name, argc, argv);
        if (str.empty()) 
        {
            return defaultValue;
        }

        return ToBoolean(str.data());
    }

    std::string GetCommandArgument(const char* name, int argc, const char** argv, const char* defaultValue) noexcept 
    {
        std::string defValue;
        if (defaultValue) 
        {
            defValue = defaultValue;
        }

        return GetCommandArgument(name, argc, argv, defValue);
    }

    std::string GetCommandArgument(const char* name, int argc, const char** argv, const std::string& defaultValue) noexcept 
    {
        std::string str = GetCommandArgument(name, argc, argv);
        return str.empty() ? defaultValue : str;
    }

    bool IsInputHelpCommand(int argc, const char* argv[]) noexcept 
    {
        const int HELP_COMMAND_COUNT = 4;
        const char* HELP_COMMAND_LIST[HELP_COMMAND_COUNT] = 
        {
            "-h",
            "--h",
            "-help",
            "--help"
        };

        for (int i = 0; i < HELP_COMMAND_COUNT; i++) 
        {
            const char* command = HELP_COMMAND_LIST[i];
            if (HasCommandArgument(command, argc, argv)) 
            {
                return true;
            }
        }
        return false;
    }

    bool HasCommandArgument(const char* name, int argc, const char** argv) noexcept 
    {
        if (NULL == name || *name == '\x0') {
            return false;
        }

        std::string commandText = GetCommandArgument(argc, argv);
        if (commandText.empty()) 
        {
            return false;
        }

        auto fx =
            [](std::string& commandText, const std::string& name) noexcept -> bool 
            {
                std::size_t index = commandText.find(name);
                if (index == std::string::npos) 
                {
                    return false;
                }

                if (index == 0) 
                {
                    return true;
                }

                char ch = commandText[index - 1];
                if (ch == ' ') 
                {
                    return true;
                }
                else 
                {
                    return false;
                }
            };

        bool result = false;
        result = result || fx(commandText, name + std::string("="));
        result = result || fx(commandText, name + std::string(" "));
        return result;
    }

    std::string GetCommandArgument(int argc, const char** argv) noexcept 
    {
        if (NULL == argv || argc <= 1) 
        {
            return "";
        }

        std::string line;
        for (int i = 1; i < argc; i++) 
        {
            line.append(RTrim(LTrim<std::string>(argv[i])));
            line.append(" ");
        }

        return line;
    }

    std::string GetCommandArgument(const char* name, int argc, const char** argv) noexcept 
    {
        if (NULL == name || argc <= 1) 
        {
            return "";
        }

        std::string key1 = name;
        if (key1.empty()) 
        {
            return "";
        }

        std::string key2 = key1 + " ";
        key1.append("=");

        std::string line = GetCommandArgument(argc, argv);
        if (line.empty()) {
            return "";
        }

        std::string* key = addressof(key1);
        std::size_t L = line.find(*key);
        if (L == std::string::npos) 
        {
            key = addressof(key2);
            L = line.find(*key);
            if (L == std::string::npos) 
            {
                return "";
            }
        }

        if (L) 
        {
            char ch = line[L - 1];
            if (ch != ' ') 
            {
                return "";
            }
        }

        std::string cmd;
        std::size_t M = L + key->size();
        std::size_t R = line.find(' ', L);
        if (M >= R)
        {
            R = std::string::npos;
            for (std::size_t I = M, SZ = line.size(); I < SZ; I++) 
            {
                int ch = line[I];
                if (ch == ' ')
                {
                    R = I;
                    L = M;
                    break;
                }
            }

            if (!L || L == std::string::npos) 
            {
                return "";
            }
        }

        if (R == std::string::npos) 
        {
            if (M != line.size()) 
            {
                cmd = line.substr(M);
            }
        }
        else
        {
            int S = (int)(R - M);
            if (S > 0) 
            {
                cmd = line.substr(M, S);
            }
        }
        return cmd;
    }
}