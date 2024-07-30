#pragma once

#include "stdafx.h"

namespace aggligator
{
    static constexpr int AGGLIGATOR_RECONNECT_TIMEOUT = 5;
    static constexpr int AGGLIGATOR_CONNECT_TIMEOUT   = 5;
    static constexpr int AGGLIGATOR_INACTIVE_TIMEOUT  = 72;

    class aggligator : public std::enable_shared_from_this<aggligator>
    {
        class                                                                   server;
        typedef std::shared_ptr<server>                                         server_ptr;

        class                                                                   client;
        typedef std::shared_ptr<client>                                         client_ptr;

        class                                                                   connection;
        typedef std::shared_ptr<connection>                                     connection_ptr;

        class                                                                   convergence;
        typedef std::shared_ptr<convergence>                                    convergence_ptr;

        typedef std::shared_ptr<aggligator>                                     ptr;

        struct send_packet
        {
            std::shared_ptr<Byte>                                               packet;
            int                                                                 length;
        };

    public:
        class information
        {
        public:
            uint64_t                                                            rx;
            uint64_t                                                            tx;
            uint64_t                                                            rx_pps;
            uint64_t                                                            tx_pps;
            uint32_t                                                            client_count;
            uint32_t                                                            connection_count;
            uint32_t                                                            establish_count;
            unordered_set<int>                                                  bind_ports;
            unordered_set<boost::asio::ip::tcp::endpoint>                       server_endpoints;
        };

    public:
        aggligator(boost::asio::io_context& context, const std::shared_ptr<Byte>& buffer, int buffer_size, int congestions) noexcept;
        ~aggligator() noexcept;

    public:
        std::function<void()>                                                   Exit;
        std::function<void(uint64_t)>                                           Tick;

    public:
        void                                                                    close() noexcept;
        bool                                                                    server_open(const unordered_set<int>& bind_ports, const boost::asio::ip::address& destination_ip, int destination_port) noexcept;
        bool                                                                    client_open(
            int                                                                 connections, 
            int                                                                 bind_port,
            const unordered_set<boost::asio::ip::tcp::endpoint>&                servers) noexcept;
        uint64_t                                                                now() noexcept { return now_; }
        void                                                                    update(uint64_t now) noexcept;
        bool                                                                    info(information& i) noexcept;
        bool                                                                    server_mode() noexcept { return server_mode_; }

    public:
        enum link_status
        {
            link_status_none = 0,
            link_status_unknown = 1,
            link_status_connecting = 2,
            link_status_reconnecting = 3,
            link_status_established = 4,
        };
        link_status                                                             status() noexcept;
        link_status                                                             status(information& i) noexcept;

    public:
        static void                                                             socket_flash_mode(bool value) noexcept;

        static void                                                             socket_adjust(int sockfd, bool in4) noexcept;

        static void                                                             deadline_timer_cancel(deadline_timer& t) noexcept;

        static void                                                             socket_close(boost::asio::ip::udp::socket& socket) noexcept;

        static void                                                             socket_close(boost::asio::ip::tcp::socket& socket) noexcept;

        static bool                                                             socket_adjust(boost::asio::ip::tcp::socket& socket) noexcept;

        static bool                                                             socket_adjust(boost::asio::ip::udp::socket& socket) noexcept;

        static bool                                                             socket_adjust(boost::asio::ip::tcp::acceptor& socket) noexcept;

        static bool                                                             ip_is_invalid(const boost::asio::ip::address& address) noexcept;

#if defined(JEMALLOC)
        static void                                                             jemaillc_areans_set_default() noexcept;
#endif

        static boost::asio::ip::udp::endpoint                                   ip_v6_to_v4(const boost::asio::ip::udp::endpoint& ep) noexcept;

        static boost::asio::ip::tcp::endpoint                                   ip_v6_to_v4(const boost::asio::ip::tcp::endpoint& ep) noexcept;

        static boost::asio::ip::udp::endpoint                                   ip_v4_to_v6(const boost::asio::ip::udp::endpoint& ep) noexcept;

        static boost::asio::ip::tcp::endpoint                                   ip_v4_to_v6(const boost::asio::ip::tcp::endpoint& ep) noexcept;

        virtual std::shared_ptr<Byte>                                           make_shared_bytes(int length) noexcept;

    private:
        bool                                                                    client_reopen(client* client) noexcept;
        bool                                                                    server_closed(client* client) noexcept;
        bool                                                                    server_accept(const acceptor& acceptor) noexcept;
        bool                                                                    server_accept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::yield_context& y) noexcept;
        bool                                                                    create_timeout() noexcept;
        bool                                                                    nawait_timeout() noexcept;

    private:
        boost::asio::io_context&                                                context_;
        std::shared_ptr<Byte>                                                   buffer_;
        int                                                                     buffer_size_;
        int                                                                     congestions_;
        bool                                                                    server_mode_;
        uint32_t                                                                last_;
        uint64_t                                                                now_;
        uint64_t                                                                rx_;
        uint64_t                                                                tx_;
        uint64_t                                                                rx_pps_;
        uint64_t                                                                tx_pps_;
        server_ptr                                                              server_;
        client_ptr                                                              client_;
        deadline_timer                                                          reopen_;
        deadline_timer                                                          timeout_;
    };
}