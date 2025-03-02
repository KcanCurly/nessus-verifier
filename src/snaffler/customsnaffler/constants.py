import enum

class EnumerationScope(enum.Enum):
	Directory = 'Directory'
	File = 'File'
	Content = 'Content'

class MatchLoc(enum.Enum):
	FilePath = 'FilePath'
	FileName = 'FileName'
	FileExtension = 'FileExtension'
	FileContentAsString = 'FileContentAsString'
	FileContentAsBytes = 'FileContentAsBytes'
	FileLength = 'FileLength'
	FileMD5 = 'FileMD5'

class MatchListType(enum.Enum):
	Exact = 'Exact'
	Contains = 'Contains'
	Regex = 'Regex'
	EndsWith = 'EndsWith'
	StartsWith = 'StartsWith'

class MatchAction(enum.Enum):
	Discard = 'Discard'
	SendToNextScope = 'SendToNextScope'
	Snaffle = 'Snaffle'
	Relay = 'Relay'
	CheckForKeys = 'CheckForKeys'
	EnterArchive = 'EnterArchive'

class Triage(enum.Enum):
	Black = 'black'
	Green = 'green'
	Blue = 'blue'
	Yellow = 'yellow'
	Red = 'red'
	Gray = 'gray'