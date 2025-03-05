from src.snaffler.customsnaffler.constants import EnumerationScope, MatchAction, MatchLoc, MatchListType, Triage
from src.snaffler.customsnaffler.rule import SnaffleRule
from typing import List

class SnafflerDirectoryRule(SnaffleRule):
	def match(self, data):
		for rex in self.wordList:
			if rex.search(data):
				return True
		return False

	def determine_action(self, data):
		if not self.match(data):
			return None, None
		return self.action, self.triage