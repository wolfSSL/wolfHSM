#!/bin/bash

set -o noclobber -o nounset || exit $?
shopt -s extglob || exit $?

retval=0

if [[ -n "${CLANG_TIDY:-}" ]]; then

    while :; do

	for arg in "$@"; do
	    case "$arg" in
		*.c) source_file="$arg"
		     ;;
	    esac
	done
	unset arg

	if [[ -z "${source_file:-}" ]]; then
	    retval=0
	    break
	fi

	# Skip clang-tidy analysis for wolfSSL dependency files
	# Only analyze wolfHSM source code (src/ and wolfhsm/ directories)
	if [[ "$source_file" == */wolfssl/* ]]; then
	    retval=0
	    break
	fi

    # Only analyze wolfHSM sources: src/ and wolfhsm/ (skip others, e.g., test/, tools/, wolfssl/)
    if [[ ! "$source_file" == */src/* && ! "$source_file" == */wolfhsm/* ]]; then
        retval=0
        break
    fi

    # Always declare the array (avoid unbound errors under set -u)
    declare -a clang_tidy_args_array=()
    # Build argument array only if CLANG_TIDY_ARGS is present
    if [[ -n "${CLANG_TIDY_ARGS:-}" ]]; then
        read -r -a clang_tidy_args_array < <(echo "${CLANG_TIDY_ARGS}") || exit $?
    fi

	if [[ -n "${CLANG_TIDY_PER_FILE_CHECKS:-}" ]]; then
	    per_file_checks=()
	    read -r -a clang_tidy_per_file_checks < <(echo "$CLANG_TIDY_PER_FILE_CHECKS") || exit $?
	    for check in "${clang_tidy_per_file_checks[@]}"; do
		if [[ "$source_file" =~ ${check%:*} ]]; then
		    per_file_checks+=("${check#*:}")
		fi
	    done
	    unset check
	fi

	if [[ -n "${per_file_checks:-}" ]]; then
	    declare -i i=0
	    while [[ $i -lt ${#clang_tidy_args_array[@]} ]]; do
		if [[ "${clang_tidy_args_array[i]}" =~ ^-checks ]]; then
		    SAVE_IFS="$IFS"
		    IFS=,
		    clang_tidy_args_array[i]="${clang_tidy_args_array[i]},${per_file_checks[*]}"
		    IFS="$SAVE_IFS"
		    added_to_existing_checks=
		    break
		fi
		: $((++i))
	    done
	    if [[ -z "${added_to_existing_checks:-}" ]]; then
		SAVE_IFS="$IFS"
		IFS=,
		clang_tidy_args_array+=("-checks=${per_file_checks[*]}")
		IFS="$SAVE_IFS"
	    fi
	fi

	if [[ -n "${CLANG_TIDY_PER_FILE_ARGS:-}" ]]; then
	    read -r -a clang_tidy_per_file_args < <(echo "$CLANG_TIDY_PER_FILE_ARGS") || exit $?
	    for arg in "${clang_tidy_per_file_args[@]}"; do
		if [[ "$source_file" =~ ${arg%:*} ]]; then
		    clang_tidy_args_array+=("${arg#*:}")
		fi
	    done
	    unset arg
	fi

	if [[ -n "${CLANG_TIDY_CONFIG:-}" ]]; then
	    clang_tidy_args_array+=("-config=${CLANG_TIDY_CONFIG}")
	fi

	if [[ -n "${CLANG_TIDY_EXTRA_ARGS:-}" ]]; then
	    read -r -a clang_tidy_extra_args < <(echo "$CLANG_TIDY_EXTRA_ARGS") || exit $?
	    clang_tidy_args_array+=("${clang_tidy_extra_args[@]}")
	fi

    if [[ ${#clang_tidy_args_array[@]} -gt 0 ]]; then
        for arg in "${clang_tidy_args_array[@]}"; do
	    case "$arg" in
		--use-color) use_color=
			     ;;
	    esac
        done
    fi
	unset arg

	if [[ -n "${use_color:-}" ]]; then
	    if text_normal_start="$(tput sgr0)"; then
		do_style_restore=
	    fi
	fi

	while read -r clang_tidy_line; do
	    case "$clang_tidy_line" in
		Use\ -header-filter=.*\ to\ display\ errors\ from\ all\ non-system\ headers.\ Use\ -system-headers\ to\ display\ errors\ from\ system\ headers\ as\ well.)

		    [[ -n "${do_style_restore:-}" ]] && echo -n "$text_normal_start" >&2
		    ;;

		+([0-9])\ warning?(s)\ generated.)

		    [[ -n "${do_style_restore:-}" ]] && echo -n "$text_normal_start" >&2
		    ;;

		Suppressed\ +([0-9])\ warnings\ \(+([0-9])\ NOLINT\).)

		    IFS="[( ]" read -r -a clang_tidy_line_a < <(echo "$clang_tidy_line")
		    if [[ "${clang_tidy_line_a[3]}" == "${clang_tidy_line_a[1]}" ]]; then
			[[ -n "${do_style_restore:-}" ]] && echo -n "$text_normal_start" >&2
		    else
			echo "$clang_tidy_line" >&2
		    fi
		    ;;

		Suppressed\ +([0-9])\ warnings\ \(+([0-9])\ in\ non-user\ code,\ +([0-9])\ NOLINT\).)

		    IFS="[( ]" read -r -a clang_tidy_line_a < <(echo "$clang_tidy_line")
		    if [[ $((clang_tidy_line_a[3] + clang_tidy_line_a[7])) == "${clang_tidy_line_a[1]}" ]]; then
			[[ -n "${do_style_restore:-}" ]] && echo -n "$text_normal_start" >&2
		    else
			echo "$clang_tidy_line" >&2
		    fi
		    ;;

		Suppressed\ +([0-9])\ warnings\ \(+([0-9])\ with\ check\ filters\).)

		    IFS="[( ]" read -r -a clang_tidy_line_a < <(echo "$clang_tidy_line")
		    if [[ "${clang_tidy_line_a[3]}" == "${clang_tidy_line_a[1]}" ]]; then
			[[ -n "${do_style_restore:-}" ]] && echo -n "$text_normal_start" >&2
		    else
			echo "$clang_tidy_line" >&2
		    fi
		    ;;

		Suppressed\ +([0-9])\ warnings\ \(+([0-9])\ in\ non-user\ code,\ +([0-9])\ with\ check\ filters\).)

		    IFS="[( ]" read -r -a clang_tidy_line_a < <(echo "$clang_tidy_line")
		    if [[ $((clang_tidy_line_a[3] + clang_tidy_line_a[7])) == "${clang_tidy_line_a[1]}" ]]; then
			[[ -n "${do_style_restore:-}" ]] && echo -n "$text_normal_start" >&2
		    else
			echo "$clang_tidy_line" >&2
		    fi
		    ;;

		Suppressed\ +([0-9])\ warnings\ \(+([0-9])\ in\ non-user\ code,\ +([0-9])\ NOLINT,\ +([0-9])\ with\ check\ filters\).)

		    IFS="[( ]" read -r -a clang_tidy_line_a < <(echo "$clang_tidy_line")
		    if [[ $((clang_tidy_line_a[3] + clang_tidy_line_a[7] + clang_tidy_line_a[9])) == "${clang_tidy_line_a[1]}" ]]; then
			[[ -n "${do_style_restore:-}" ]] && echo -n "$text_normal_start" >&2
		    else
			echo "$clang_tidy_line" >&2
		    fi
		    ;;

		Suppressed\ +([0-9])\ warnings\ \(+([0-9])\ due\ to\ line\ filter\).)

		    IFS="[( ]" read -r -a clang_tidy_line_a < <(echo "$clang_tidy_line")
		    if [[ "${clang_tidy_line_a[3]}" == "${clang_tidy_line_a[1]}" ]]; then
			[[ -n "${do_style_restore:-}" ]] && echo -n "$text_normal_start" >&2
		    else
			echo "$clang_tidy_line" >&2
		    fi
		    ;;

		Suppressed\ +([0-9])\ warnings\ \(+([0-9])\ in\ non-user\ code,\ +([0-9])\ due\ to\ line\ filter\).)

		    IFS="[( ]" read -r -a clang_tidy_line_a < <(echo "$clang_tidy_line")
		    if [[ $((clang_tidy_line_a[3] + clang_tidy_line_a[7])) == "${clang_tidy_line_a[1]}" ]]; then
			[[ -n "${do_style_restore:-}" ]] && echo -n "$text_normal_start" >&2
		    else
			echo "$clang_tidy_line" >&2
		    fi
		    ;;

		Suppressed\ +([0-9])\ warnings\ \(+([0-9])\ due\ to\ line\ filter,\ +([0-9])\ NOLINT\).)

		    IFS="[( ]" read -r -a clang_tidy_line_a < <(echo "$clang_tidy_line")
		    if [[ $((clang_tidy_line_a[3] + clang_tidy_line_a[7])) == "${clang_tidy_line_a[1]}" ]]; then
			[[ -n "${do_style_restore:-}" ]] && echo -n "$text_normal_start" >&2
		    else
			echo "$clang_tidy_line" >&2
		    fi
		    ;;

		Suppressed\ +([0-9])\ warnings\ \(+([0-9])\ in\ non-user\ code,\ +([0-9])\ due\ to\ line\ filter,\ +([0-9])\ NOLINT\).)

		    IFS="[( ]" read -r -a clang_tidy_line_a < <(echo "$clang_tidy_line")
		    if [[ $((clang_tidy_line_a[3] + clang_tidy_line_a[7] + clang_tidy_line_a[12])) == "${clang_tidy_line_a[1]}" ]]; then
			[[ -n "${do_style_restore:-}" ]] && echo -n "$text_normal_start" >&2
		    else
			echo "$clang_tidy_line" >&2
		    fi
		    ;;

		Suppressed\ +([0-9])\ warnings\ \(+([0-9])\ in\ non-user\ code\).)

		    IFS="[( ]" read -r -a clang_tidy_line_a < <(echo "$clang_tidy_line")
		    if [[ "${clang_tidy_line_a[1]}" == "${clang_tidy_line_a[3]}" ]]; then
			[[ -n "${do_style_restore:-}" ]] && echo -n "$text_normal_start" >&2
		    else
			echo "$clang_tidy_line" >&2
		    fi
		    ;;

		*)

		    echo "$clang_tidy_line" >&2
		    retval=1
		    ;;

            esac

        done < <("$CLANG_TIDY" ${clang_tidy_args_array+"${clang_tidy_args_array[@]}"} "$source_file" -- "$@" 2>&1)

	if [[ "$retval" != '0' && -n "${do_style_restore:-}" ]]; then
	    echo -n "$text_normal_start" >&2
	fi
	break
    done
fi

if [[ "$retval" != '0' ]]; then
    exit "$retval"
fi

# shellcheck disable=SC2162 # intentional use of read with process substitution; -r flag is present and safe.
if [[ -n "${CLANG_OVERRIDE_CFLAGS:-}" ]]; then
    read -r -a CLANG_OVERRIDE_CFLAGS_a < <(echo "${CLANG_OVERRIDE_CFLAGS}")
    exec "$CLANG" "$@" "${CLANG_OVERRIDE_CFLAGS_a[@]}"
else
    exec "$CLANG" "$@"
fi
