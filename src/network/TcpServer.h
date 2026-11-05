
#pragma once

#include <boost/asio.hpp>
#include <functional>
#include <memory>
#include <cstdint>

class TcpServer
{
public:
    using Socket = boost::asio::ip::tcp::socket;
    using ConnectionHandler =
        std::function<void(std::shared_ptr<Socket>)>;

    TcpServer(
        boost::asio::io_context& io,
        uint16_t port,
        ConnectionHandler handler
    );

    void Start();
    void Stop();

private:
    void Accept();

    boost::asio::io_context& io_;
    boost::asio::ip::tcp::acceptor acceptor_;
    ConnectionHandler handler_;
    bool running_ = false;
};
