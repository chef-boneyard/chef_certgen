REBAR=rebar

all: compile test

compile:
	@$(REBAR) compile

clean:
	@$(REBAR) clean

test:
	@$(REBAR) eunit skip_deps=true

.PHONY: test doc
