
#include "TcpServer.h"

#include <iostream>

TcpServer::TcpServer(
    boost::asio::io_context& io,
    uint16_t port,
    ConnectionHandler handler)
    : io_(io),
      acceptor_(io),
      handler_(std::move(handler))
{
    boost::asio::ip::tcp::endpoint endpoint(
        boost::asio::ip::tcp::v4(),
        port
    );

    acceptor_.open(endpoint.protocol());
    acceptor_.set_option(
        boost::asio::ip::tcp::acceptor::reuse_address(true)
    );

    acceptor_.bind(endpoint);
    acceptor_.listen(
        boost::asio::socket_base::max_listen_connections
    );
}

void TcpServer::Start()
{
    if (running_)
        return;

    running_ = true;
    Accept();
}

void TcpServer::Accept()
{
    if (!running_)
        return;

    auto socket = std::make_shared<Socket>(io_);

    acceptor_.async_accept(
        *socket,
        [this, socket](const boost::system::error_code& error)
        {
            if (!error && running_)
            {
                try
                {
                    handler_(socket);
                }
                catch (const std::exception& e)
                {
                    std::cerr << "Connection error: "
                              << e.what() << '\n';
                }
            }

            if (running_)
                Accept();
        }
    );
}

void TcpServer::Stop()
{
    running_ = false;

    boost::system::error_code error;
    acceptor_.close(error);
}
