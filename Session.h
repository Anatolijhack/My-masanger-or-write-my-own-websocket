#pragma once
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>
#include <unordered_map>
#include "ThreadPool.h"
#include "Router.h"

#include <queue>

using boost::asio::ip::tcp;
class Session : public std::enable_shared_from_this<Session>
{
private:
	enum class ParseState
	{
		RequestLine,
		Header,
		Body
	};
	enum class ParseResult
	{
		Incomplete,
		Complete,
		Error
	};
	void do_shutdown();
	std::string websocket_fragment_buffer;
	bool websocket_fragmented = false;
	ParseState state = ParseState::RequestLine;
	std::string path;
	std::string version;
	std::string method;
	std::unordered_map<std::string, std::string> headers;
	std::array<char, 4096> temp;
	int content_lenght = 0;
bool is_valid_utf8(
    const std::string& data);	std::deque<std::shared_ptr<std::string>> write_queue;
	bool writing = false;
	boost::asio::ssl::stream<tcp::socket> socket;
	std::string buffer;
	Router& router;
	std::string body;
	bool keep_alive = true;
	int content_length = 0;
	static constexpr std::size_t MAX_REQUEST_SIZE = 10 * 1024 * 1024;
	ThreadPool& pool;
	void do_write();
	void send_websocket_close();
	void do_read();
	/*bool parse();*/
	ParseResult parse();
	void process_request();
	void reset_parser();
	void send_response(const std::string& body,
		const std::string& type,
		const std::string& status);
	void send_response_safe(const std::string& body,
		const std::string& type,
		const std::string& status);
	bool websocket_mode = false;
	bool websocket_fragment_binary = false;

	bool is_websocket_request() const;
	void do_websocket_handshake();
	void do_websocket_read();
	void send_websocket_text(const std::string& message);
	void send_websocket_binary(const std::string& data);
	void send_websocket_pong(const std::string& payload);
bool is_valid_websocket_close_code(
    std::uint16_t code);
public:
	Session(tcp::socket socket, ThreadPool& pool, Router& router, boost::asio::ssl::context& ssl_context);
	void start();
};