#pragma once
#include <string>
#include <iostream>
#include <unordered_map>
struct Request
{
    std::string method;
    std::string path;
    std::string body;
    std::unordered_map<std::string, std::string> params;
    std::unordered_map<std::string, std::string> headers;
};

struct Response
{
    std::string body;
    std::string content_type = "text/plain";
    std::string status = "200 OK";
};