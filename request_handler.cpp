//
// request_handler.cpp
// ~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2015 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "request_handler.hpp"
#include <fstream>
#include <sstream>
#include <string>
#include "mime_types.hpp"
#include "reply.hpp"
#include "request.hpp"
#include <boost/uuid/sha1.hpp>
#include <boost/shared_array.hpp>
#include <iostream>
#include "Base64Utilities.hpp"

#pragma warning(disable: 4996) //4996 for _CRT_SECURE_NO_WARNINGS equivalent

namespace http {
namespace server {

request_handler::request_handler(const std::string& doc_root)
  : doc_root_(doc_root)
{
}
void display(char* hash)
{
	std::cout << "SHA1: " << std::hex;
	for (int i = 0; i < 20; ++i)
	{
		std::cout << ((hash[i] & 0x000000F0) >> 4)
			<< (hash[i] & 0x0000000F);
	}
	std::cout << std::endl; // Das wars  
}


std::string sha1_to_string(const char *hash)
{
	char str[128] = { 0 };
	char *ptr = str;
	std::string ret;

	for (int i = 0; i < 20; i++)
	{
		sprintf(ptr, "%02X", (unsigned char)*hash);
		ptr += 2;
		hash++;
	}
	ret = str;

	return ret;
}

std::string compute_seckey(const std::string& client_key)
{
	std::string s = client_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

	boost::uuids::detail::sha1 hasher;
	boost::shared_array<unsigned int> digest;

	digest.reset(new unsigned int[5]);
	char bin[20];

	hasher.process_bytes(s.c_str(), s.size());
	hasher.get_digest(reinterpret_cast<boost::uuids::detail::sha1::digest_type>(*digest.get()));
	for (int i = 0; i < 5; ++i)
	{
		const char* tmp = reinterpret_cast<char*>(digest.get());
		bin[i * 4] = tmp[i * 4 + 3];
		bin[i * 4 + 1] = tmp[i * 4 + 2];
		bin[i * 4 + 2] = tmp[i * 4 + 1];
		bin[i * 4 + 3] = tmp[i * 4];
	}

	//std::string hash_hex = sha1_to_string(bin);

	// output hex digest
	//std::cout << hash_hex.c_str() << std::endl;
	//std::cout << Base64Utilities::ToBase64(v) << std::endl;

	std::vector<unsigned char> v(bin, bin + sizeof bin / sizeof bin[0]);
	std::string res = Base64Utilities::ToBase64(v);

	return res;

	/*
	for (std::size_t i = 0; i<sizeof(digest) / sizeof(digest[0]); ++i) {
		//std::cout << std::hex << hash[i];
		printf("%X", digest[i]);
	}
	*/
	//char* hash = reinterpret_cast<char*>(digest);
}

void request_handler::handle_websocket_request(const request& req, reply& rep)
{

}

void request_handler::handle_request(const request& req, reply& rep)
{
	std::string seckey;
	for each ( header h in req.headers)
	{
		printf("%s: %s\n", h.name.data(), h.value.data());
		if (h.name == "Upgrade" && h.value == "websocket")
			printf("WS!!!!\n");
		else if (h.name == "Sec-WebSocket-Key")
			seckey = compute_seckey(h.value);
	}

	//std::string seckey = compute_seckey("dGhlIHNhbXBsZSBub25jZQ==");


	/*
		HTTP/1.1 101 Switching Protocols
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
	*/
	// Fill out the reply to be sent to the client.
	
	rep.status = reply::switching_protocols;
	rep.headers.resize(3);
	rep.headers[0].name = "Upgrade";
	rep.headers[0].value = "websocket";
	rep.headers[1].name = "Connection";
	rep.headers[1].value = "Upgrade";
	rep.headers[2].name = "Sec-WebSocket-Accept";
	rep.headers[2].value = seckey;
	return;

  // Decode url to path.
  std::string request_path;
  if (!url_decode(req.uri, request_path))
  {
    rep = reply::stock_reply(reply::bad_request);
    return;
  }

  // Request path must be absolute and not contain "..".
  if (request_path.empty() || request_path[0] != '/'
      || request_path.find("..") != std::string::npos)
  {
    rep = reply::stock_reply(reply::bad_request);
    return;
  }

  // If path ends in slash (i.e. is a directory) then add "index.html".
  if (request_path[request_path.size() - 1] == '/')
  {
    request_path += "index.html";
  }

  // Determine the file extension.
  std::size_t last_slash_pos = request_path.find_last_of("/");
  std::size_t last_dot_pos = request_path.find_last_of(".");
  std::string extension;
  if (last_dot_pos != std::string::npos && last_dot_pos > last_slash_pos)
  {
    extension = request_path.substr(last_dot_pos + 1);
  }

  // Open the file to send back.
  std::string full_path = doc_root_ + request_path;
  std::ifstream is(full_path.c_str(), std::ios::in | std::ios::binary);
  if (!is)
  {
    rep = reply::stock_reply(reply::not_found);
    return;
  }

  // Fill out the reply to be sent to the client.
  rep.status = reply::ok;
  char buf[512];
  while (is.read(buf, sizeof(buf)).gcount() > 0)
    rep.content.append(buf, is.gcount());
  rep.headers.resize(2);
  rep.headers[0].name = "Content-Length";
  rep.headers[0].value = std::to_string(rep.content.size());
  rep.headers[1].name = "Content-Type";
  rep.headers[1].value = mime_types::extension_to_type(extension);
}

bool request_handler::url_decode(const std::string& in, std::string& out)
{
  out.clear();
  out.reserve(in.size());
  for (std::size_t i = 0; i < in.size(); ++i)
  {
    if (in[i] == '%')
    {
      if (i + 3 <= in.size())
      {
        int value = 0;
        std::istringstream is(in.substr(i + 1, 2));
        if (is >> std::hex >> value)
        {
          out += static_cast<char>(value);
          i += 2;
        }
        else
        {
          return false;
        }
      }
      else
      {
        return false;
      }
    }
    else if (in[i] == '+')
    {
      out += ' ';
    }
    else
    {
      out += in[i];
    }
  }
  return true;
}


} // namespace server
} // namespace http