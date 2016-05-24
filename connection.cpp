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
#include "ws_frame_parser.hpp"

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
				ws_frame frame;

				frame.fin = 0x80 & buffer_[0];
				frame.masking = 0x80 & buffer_[1];

				frame.payload_len = (unsigned int)(buffer_[1] & 0x7F);
				int masking_key_offset = 0;
				// If 126, the following 2 bytes interpreted as a 16 - bit unsigned integer are the payload length.
				if (frame.payload_len == 126)
				{
					masking_key_offset = 2;
					unsigned short s = ((buffer_[2] << 8) | buffer_[3]);
					frame.payload_len = s;
				}
				// If 127, the following 8 bytes interpreted as a 64 - bit unsigned integer(the most significant bit MUST be 0) are the payload length.
				else if (frame.payload_len == 127)
				{
					unsigned long long int s = 
					(
						(buffer_[2] << 64) | (buffer_[3] << 56) | (buffer_[4] << 48) |
						(buffer_[5] << 40) | (buffer_[6] << 32) | (buffer_[7] << 24) | 
						(buffer_[8] << 12) | (buffer_[9] << 4) | buffer_[10]
					);
					frame.payload_len = s;
					masking_key_offset = 8;
				}

				if (frame.masking)
				{
					frame.masking_key[0] = (buffer_[2] + masking_key_offset);
					frame.masking_key[1] = (buffer_[3] + masking_key_offset);
					frame.masking_key[2] = (buffer_[4] + masking_key_offset);
					frame.masking_key[3] = (buffer_[5] + masking_key_offset);
				}
				else
				{
					frame.masking_key[0] = 0;
					frame.masking_key[1] = 0;
					frame.masking_key[2] = 0;
					frame.masking_key[3] = 0;
				}

				frame.payload = std::vector<unsigned char>();

	
				for (int i = 0; i < frame.payload_len; ++i)
				{
					unsigned char original = buffer_[6 + masking_key_offset + i];
					frame.payload.push_back(original ^ frame.masking_key[i % 4]);
				}
				
				printf("masking: %s\n payload: %d bytes\n", frame.masking ? "True" : "False", frame.payload_len);
				printf("Data: %s\n", frame.payload.data());

				//do_write("Data: %s\n", 5);
				do_read();
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

void connection::do_write(const void* data, int size)
{
	auto self(shared_from_this());
	boost::asio::async_write(socket_, boost::asio::buffer(data, size),
		[this, self](boost::system::error_code ec, std::size_t)
	{
		if (!ec)
		{
			do_read();
		}
	});
}

} // namespace server
} // namespace http