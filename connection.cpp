//
// connection.cpp
// ~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2015 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "connection.hpp"
#include <utility>
#include <vector>
#include "connection_manager.hpp"
#include "request_handler.hpp"

namespace http {
namespace server {
	bool ws_connected;
connection::connection(boost::asio::ip::tcp::socket socket,
    connection_manager& manager, request_handler& handler)
  : socket_(std::move(socket)),
    connection_manager_(manager),
    request_handler_(handler)
{
}

void connection::start()
{
	ws_connected = false;
  do_read();
}

void connection::stop()
{
  socket_.close();
}

void connection::do_read()
{
  auto self(shared_from_this());
  socket_.async_read_some(boost::asio::buffer(buffer_),
      [this, self](boost::system::error_code ec, std::size_t bytes_transferred)
      {
        if (!ec)
        {
			if (ws_connected)
			{
				printf(buffer_.data());
				return;
			}

          request_parser::result_type result;
          std::tie(result, std::ignore) = request_parser_.parse(
              request_, buffer_.data(), buffer_.data() + bytes_transferred);

          if (result == request_parser::good)
          {
            request_handler_.handle_request(request_, reply_);
			if (reply_.status == reply::switching_protocols)
			{
				ws_connected = true;
			}
			do_write_http();
          }
          else if (result == request_parser::bad)
          {
            reply_ = reply::stock_reply(reply::bad_request);
			do_write_http();
          }
          else
          {
            do_read();
          }
        }
        else if (ec != boost::asio::error::operation_aborted)
        {
          connection_manager_.stop(shared_from_this());
        }
      });
}

void connection::do_write_http()
{
  auto self(shared_from_this());
  boost::asio::async_write(socket_, reply_.to_buffers(),
      [this, self](boost::system::error_code ec, std::size_t)
      {
        if (!ec)
        {
          // Initiate graceful connection closure.
          //boost::system::error_code ignored_ec;
          //socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both,
          //  ignored_ec);
			printf("Client connected to WS\n");
			do_read();
        }
		/*
        if (ec != boost::asio::error::operation_aborted)
        {
          connection_manager_.stop(shared_from_this());
        }
		*/
      });
}

} // namespace server
} // namespace http