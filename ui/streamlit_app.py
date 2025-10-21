import streamlit as st
import subprocess
import sys
import os
import time
import pandas as pd

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
# Ensure the project root is on sys.path so imports like `from config import settings` work
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
try:
    from config import settings
except Exception as e:
    # Provide a clearer error message in the UI if import fails
    raise ImportError(f"Failed to import project package 'config'. Make sure you run Streamlit from the project root or that the project root ({ROOT}) is accessible. Original error: {e}")


def run_script(args: list, timeout: int = 3600):
    """Run a Python script using the current Python executable and capture output."""
    cmd = [sys.executable] + args
    try:
        start = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = time.time() - start
        return proc.returncode, proc.stdout, proc.stderr, elapsed
    except subprocess.TimeoutExpired as e:
        return -1, "", f"Timeout after {timeout}s", timeout
    except Exception as e:
        return -2, "", str(e), 0


def run_script_stream(args: list, timeout: int = 3600, text_area_height: int = 300):
    """Run a Python script and stream stdout/stderr lines back to the UI.

    Returns (returncode, full_output, elapsed_seconds)
    """
    cmd = [sys.executable] + args
    start = time.time()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, text=True)
    except Exception as e:
        return -2, str(e), 0

    out_buf = []
    placeholder = st.empty()
    try:
        # Read lines as they come and update the UI text area
        for line in proc.stdout:
            out_buf.append(line)
            # update UI with the accumulated output
            try:
                placeholder.text_area("Process output (live)", ''.join(out_buf), height=text_area_height)
            except Exception:
                # ignore UI update errors
                pass
            # check timeout
            if time.time() - start > timeout:
                proc.kill()
                return -1, ''.join(out_buf) + f"\nTimeout after {timeout}s\n", timeout
        rc = proc.wait()
        elapsed = time.time() - start
        return rc, ''.join(out_buf), elapsed
    except Exception as e:
        try:
            proc.kill()
        except Exception:
            pass
        return -3, ''.join(out_buf) + f"\nError: {e}", time.time() - start


def show_dataset_summary(ds_path: str):
    """Load dataset at ds_path and display preview and summary metrics/charts."""
    try:
        if os.path.exists(ds_path):
            df = pd.read_csv(ds_path)
            st.subheader("Dataset preview")
            st.write(f"Loaded {len(df)} rows from {ds_path}")
            try:
                if st.session_state.get('show_full_tables', False):
                    st.dataframe(df)
                else:
                    st.dataframe(df.head(200))
            except Exception:
                # fallback
                st.dataframe(df.head(200))

            total = len(df)
            num_attacks = int(df['attack_flag'].sum()) if 'attack_flag' in df.columns else None
            num_replays = int(df['is_replay'].sum()) if 'is_replay' in df.columns else None
            num_randoms = int(df['is_random_guess'].sum()) if 'is_random_guess' in df.columns else None

            cols = st.columns(3)
            cols[0].metric("Total records", total)
            if num_attacks is not None:
                cols[1].metric("Attacks", num_attacks)
            if num_replays is not None:
                cols[2].metric("Replays", num_replays)

            chart_data = {}
            if num_attacks is not None:
                chart_data['attacks'] = num_attacks
            if num_replays is not None:
                chart_data['replays'] = num_replays
            if num_randoms is not None:
                chart_data['random_guesses'] = num_randoms

            if chart_data:
                st.subheader("Attack breakdown")
                try:
                    st.bar_chart(pd.DataFrame.from_dict(chart_data, orient='index', columns=['count']))
                except Exception:
                    st.write(chart_data)
        else:
            st.info(f"No dataset found at {ds_path}")
    except Exception as e:
        st.error(f"Failed to load dataset: {e}")


def page_generate_dataset():
    st.header("Generate Dataset")
    sessions = st.number_input("Number of sessions", min_value=1, value=1000)
    attack_rate = st.slider("Attack rate", 0.0, 1.0, 0.2, 0.01)
    replay_prob = st.slider("Replay probability", 0.0, 1.0, 0.6, 0.01)
    enable_attacker = st.checkbox("Enable attacker thread", value=True)
    allow_overwrite = st.checkbox("Allow overwrite of existing dataset file (auth_dataset.csv)", value=False)
    st.write("If you do not allow overwrite, the generator will not run and you can instead analyze the existing dataset.")
    save_timestamped = st.checkbox("Save to a new timestamped dataset file instead of overwriting (recommended)", value=True)

    if st.button("Analyze existing dataset"):
        ds_path = os.path.join(settings.DATA_DIR, settings.DATASET_FILENAME)
        show_dataset_summary(ds_path)
        return

    if st.button("Run generate_dataset.py"):
        ds_path = os.path.join(settings.DATA_DIR, settings.DATASET_FILENAME)
        if os.path.exists(ds_path) and not allow_overwrite:
            st.warning("Dataset already exists and overwrite is not allowed. Use 'Analyze existing dataset' or enable 'Allow overwrite' to proceed.")
            return
        args = [os.path.join(ROOT, 'generate_dataset.py'), '--sessions', str(sessions), '--attack-rate', str(attack_rate), '--replay-prob', str(replay_prob)]
        if not enable_attacker:
            args.append('--no-attacker')
        ds_name = None
        if save_timestamped:
            import datetime
            ds_name = f"auth_dataset_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            args += ['--dataset-filename', ds_name]
        with st.spinner('Running simulator... this may take a while'):
            code, out, elapsed = run_script_stream(args, timeout=36000, text_area_height=300)
        st.subheader("Result")
        st.write(f"Return code: {code}  Elapsed: {elapsed:.1f}s")
        if out:
            st.text_area("Final output", out, height=200)

        # attempt to show dataset preview and summary charts
        try:
            # determine which file was written: timestamped (ds_name) or default
            if ds_name:
                ds_path = os.path.join(settings.DATA_DIR, ds_name)
            else:
                ds_path = os.path.join(settings.DATA_DIR, settings.DATASET_FILENAME)

            if os.path.exists(ds_path):
                df = pd.read_csv(ds_path)
                st.subheader("Dataset preview")
                st.write(f"Loaded {len(df)} rows from {ds_path}")
                try:
                    if st.session_state.get('show_full_tables', False):
                        st.dataframe(df)
                    else:
                        st.dataframe(df.head(200))
                except Exception:
                    st.dataframe(df.head(200))

                # compute summary metrics if columns exist
                total = len(df)
                num_attacks = int(df['attack_flag'].sum()) if 'attack_flag' in df.columns else None
                num_replays = int(df['is_replay'].sum()) if 'is_replay' in df.columns else None
                num_randoms = int(df['is_random_guess'].sum()) if 'is_random_guess' in df.columns else None

                cols = st.columns(3)
                cols[0].metric("Total records", total)
                if num_attacks is not None:
                    cols[1].metric("Attacks", num_attacks)
                if num_replays is not None:
                    cols[2].metric("Replays", num_replays)

                # show a small bar chart of counts (attack/replay/random)
                chart_data = {}
                if num_attacks is not None:
                    chart_data['attacks'] = num_attacks
                if num_replays is not None:
                    chart_data['replays'] = num_replays
                if num_randoms is not None:
                    chart_data['random_guesses'] = num_randoms

                if chart_data:
                    st.subheader("Attack breakdown")
                    try:
                        st.bar_chart(pd.DataFrame.from_dict(chart_data, orient='index', columns=['count']))
                    except Exception:
                        st.write(chart_data)
            else:
                st.info(f"No dataset found at {ds_path}")
        except Exception as e:
            st.error(f"Failed to load dataset: {e}")


def page_run_simulation():
    st.header("Run Simulation (quick)")
    num_sessions = st.number_input("Num sessions", min_value=1, value=500)
    enable_attacker = st.checkbox("Enable attacker", value=False)

    if st.button("Run run_sm.py"):
        args = [os.path.join(ROOT, 'run_sm.py'), '--sessions', str(num_sessions)]
        if enable_attacker:
            args.append('--enable-attacker')
        with st.spinner('Running session manager...'):
            code, out, elapsed = run_script_stream(args, timeout=1800, text_area_height=300)
        st.write(f"Return code: {code}  Elapsed: {elapsed:.1f}s")
        if out:
            st.text_area("Final output", out, height=300)


def page_view_data_and_logs():
    st.header("Data & Logs")
    st.write("View files in the results and logs directories")
    data_dir = settings.DATA_DIR
    log_dir = settings.LOG_DIR

    st.subheader("Results files")
    try:
        files = sorted(os.listdir(data_dir)) if os.path.exists(data_dir) else []
        choice = st.selectbox("Select result file", ['-- none --'] + files)
        if choice and choice != '-- none --':
            path = os.path.join(data_dir, choice)
            if choice.lower().endswith('.csv'):
                df = pd.read_csv(path)
                st.write(f"{len(df)} rows — showing head")
                st.dataframe(df.head(200))
            else:
                st.code(open(path, 'r', encoding='utf-8', errors='ignore').read())
    except Exception as e:
        st.error(f"Failed to list results: {e}")

    st.subheader("Log files")
    try:
        files = sorted(os.listdir(log_dir)) if os.path.exists(log_dir) else []
        choice = st.selectbox("Select log file", ['-- none --'] + files, key='logs')
        if choice and choice != '-- none --':
            path = os.path.join(log_dir, choice)
            st.code(open(path, 'r', encoding='utf-8', errors='ignore').read())
    except Exception as e:
        st.error(f"Failed to list logs: {e}")


def main():
    st.title("Symmetric Key Challenge-Response — Demo UI")
    st.sidebar.title("Navigation")
    # global UI options
    show_full_tables = st.sidebar.checkbox("Show full dataset tables (may be large)", value=False)
    # persist into session_state for use by other functions
    st.session_state['show_full_tables'] = show_full_tables
    page = st.sidebar.selectbox("Go to", ["Generate Dataset", "Run Simulation", "Data & Logs"])

    if page == "Generate Dataset":
        page_generate_dataset()
    elif page == "Run Simulation":
        page_run_simulation()
    else:
        page_view_data_and_logs()


if __name__ == '__main__':
    main()
