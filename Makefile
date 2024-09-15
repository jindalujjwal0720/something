# Simple make file for node.js project

build:
	@echo Building apps...

	@echo Building server...
	@cd apps/server && npm install
	@echo Server: build complete

	@echo Building web...
	@cd apps/web && npm install
	@echo Web: build complete

	@echo Build Successful 🎉

init:
	@echo Initializing apps...

	@echo Initializing server...
	@cd apps/server && npm install
	@echo Server: init complete

	@echo Initializing web...
	@cd apps/web && npm install
	@echo Web: init complete

	@echo Init Successful 🎉

server:
	@echo Starting server...
	@cd apps/server && npm run dev

web:
	@echo Starting web...
	@cd apps/web && npm run dev