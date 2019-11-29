/*

	RandomX Sniffer by tevador <tevador@gmail.com>

	To the extent possible under law, the person who associated CC0 with
	RandomX Sniffer has waived all copyright and related or neighboring rights
	to RandomX Sniffer.

	You should have received a copy of the CC0 legalcode along with this
	work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

*/

#pragma once
#include <Windows.h>
#include "process.h"

namespace randomx {

	class ProcessList {
	public:
		ProcessList(SIZE_T allocSize = 4 * 1024 * 1024);
		~ProcessList();

		void query();
		Process currentProcess() const;
		bool moveNext();
	private:
		void* buffer_;
		SIZE_T bufferSize_;
		void* data_;
	};

}
