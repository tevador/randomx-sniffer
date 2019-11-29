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
#include <iostream>
#include <cstdint>

namespace randomx {

	enum class Round : WORD {
		Default = 0,
		NegInf = 1,
		PosInf = 2,
		Zero = 3
	};

	std::ostream& operator<<(std::ostream& os, const Round& r);

	class Thread {
	public:
		Thread(DWORD id);
		DWORD getId() const {
			return id_;
		}
		bool canAccess() const {
			return access_;
		}
		Round getRound() const {
			return round_;
		}
	private:
		DWORD id_;
		Round round_;
		bool access_;
	};

}
