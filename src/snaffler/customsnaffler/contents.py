from src.snaffler.customsnaffler.rule import SnaffleRule
from src.snaffler.customsnaffler.constants import MatchLoc

class SnafflerContentsEnumerationRule(SnaffleRule):
	def match_not(self, data):
		for notrex in self.notWordList:
			if notrex.search(data): return True
		return False
    
	def match(self, data, chars_before = 0, chars_after = 0):
		matches = []
		for rex in self.wordList:
			for match in rex.finditer(data):
				text = match.group(0)
				if self.match_not(text): continue
				

				if chars_before > 0:
					text = data[max(match.start() - chars_before, 0) : match.start()] + text
				if chars_after > 0:
					text += data[match.end() : min(match.end() + chars_after, len(data))]
				matches.append(text.strip())

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