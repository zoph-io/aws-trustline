# SAM custom build hook. Invoked by `sam build` thanks to the function's
# `Metadata: BuildMethod: makefile`. The target name MUST match the function's
# logical id (`build-{LogicalId}`).
#
# SAM runs this Makefile from a scratch copy of `iac/src/`, with `cwd` set to
# that scratch dir (not the original `iac/src/`). The symlink `trustline.py`
# pointing at the repo root is followed by SAM's CopySource step, so both
# `app.py` and the dereferenced `trustline.py` are present in the scratch
# dir by the time these `cp` lines run. They are then placed at the root of
# the artifact dir alongside the pip-installed dependencies (Lambda's zip
# layout).

# A throwaway venv keeps pip happy on PEP 668-restricted Pythons (Homebrew,
# Debian) without needing `--break-system-packages`. Dependencies are
# installed straight into $(ARTIFACTS_DIR), not into the venv, via --target.
BUILD_VENV := /tmp/aws-trustline-buildvenv

build-TrustlineFunction:
	cp app.py "$(ARTIFACTS_DIR)/"
	cp trustline.py "$(ARTIFACTS_DIR)/"
	@rm -rf $(BUILD_VENV)
	python3 -m venv $(BUILD_VENV)
	$(BUILD_VENV)/bin/pip install --upgrade pip --quiet
	$(BUILD_VENV)/bin/pip install -r requirements.txt \
		--target "$(ARTIFACTS_DIR)" \
		--platform manylinux2014_aarch64 \
		--only-binary=:all: \
		--implementation cp \
		--python-version 3.12 \
		--upgrade \
		--quiet
	@rm -rf $(BUILD_VENV)
