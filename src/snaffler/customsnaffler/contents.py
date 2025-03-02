import codecs
from src.snaffler.customsnaffler.rule import SnaffleRule
from src.snaffler.customsnaffler.constants import EnumerationScope, MatchAction, MatchLoc, MatchListType, Triage
from typing import List
import os

class SnafflerContentsEnumerationRule(SnaffleRule):
	def __init__(self, enumerationScope:EnumerationScope, id:str, ruleName:str, matchAction:MatchAction, category:list[str], relayTargets:List[str], description:str, matchLocation:MatchLoc, wordListType:MatchListType, matchLength:int, wordList:List[str], triage:Triage):
		super().__init__(enumerationScope, id, ruleName, matchAction, category, relayTargets, description, matchLocation, wordListType, matchLength, wordList, triage)
	
	def match(self, data, chars_before = 0, chars_after = 0):
		matches = []
		for rex in self.wordList:
			for match in rex.finditer(data):
				text = match.group(0)

				if chars_before > 0:
					text = data[max(match.start() - chars_before, 0) : match.start()] + text
				if chars_after > 0:
					text += data[match.end() : min(match.end() + chars_after, len(data))]
				matches.append(text)

		return matches

	def open_and_match(self, filecontent, chars_before, chars_after):
		try:
			if self.matchLocation == MatchLoc.FileContentAsString or self.matchLocation == MatchLoc.FileContentAsBytes:
				return self.action, self.match(filecontent, chars_before, chars_after)
			else:
				return self.action, []
		except Exception as e:
			return self.action, []

	def determine_action(self, data):
		pass