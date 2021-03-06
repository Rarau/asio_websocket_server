#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/insert_linebreaks.hpp>
#include <boost/archive/iterators/transform_width.hpp>

namespace Base64Utilities
{
	std::string ToBase64(std::vector<unsigned char> data)
	{
		using namespace boost::archive::iterators;

		// Pad with 0 until a multiple of 3
		unsigned int paddedCharacters = 0;
		while (data.size() % 3 != 0)
		{
			paddedCharacters++;
			data.push_back(0x00);
		}

		// Crazy typedef black magic
		typedef
			insert_linebreaks<         // insert line breaks every 76 characters
			base64_from_binary<    // convert binary values to base64 characters
			transform_width<   // retrieve 6 bit integers from a sequence of 8 bit bytes
			const unsigned char *
			, 6
			, 8
			>
			>
			, 76
			>
			base64Iterator; // compose all the above operations in to a new iterator

		// Encode the buffer and create a string
		std::string encodedString(
			base64Iterator(&data[0]),
			base64Iterator(&data[0] + (data.size() - paddedCharacters)));

		// Add '=' for each padded character used
		for (unsigned int i = 0; i < paddedCharacters; i++)
		{
			encodedString.push_back('=');
		}

		return encodedString;
	}
}