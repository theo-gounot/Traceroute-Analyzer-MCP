import pandas as pd
import io

def to_toon(df: pd.DataFrame) -> str:
    """
    Converts a DataFrame to a Token Oriented Object Notation (TOON) string.
    Format: Pipe-separated values with concise formatting.
    """
    # Create a copy to avoid modifying the original dataframe
    df_out = df.copy()

    # Format timestamps to ISO
    for col in df_out.select_dtypes(include=['datetime', 'datetimetz']).columns:
        df_out[col] = df_out[col].apply(lambda x: x.isoformat() if pd.notnull(x) else "")

    # Format floats to .4g manually to ensure consistency across columns
    # We convert them to string to avoid to_csv re-formatting them
    for col in df_out.select_dtypes(include=['float', 'float64']).columns:
        df_out[col] = df_out[col].apply(lambda x: f'{x:.4g}' if pd.notnull(x) else None)

    # Use to_csv with pipe separator
    # We use a string buffer to capture the output
    output_buffer = io.StringIO()
    
    # We want to avoid quoting if possible to save tokens, but need to be safe.
    # If we want strictly what the user asked: "pipe-separated table... data values separated by | "
    # We can try to force no quoting, but if data contains pipes, it breaks.
    # Assuming standard CSV behavior is acceptable but using | as separator.
    # To minimize tokens, we can suppress quoting for non-special strings.
    # But pandas to_csv quoting is all or nothing or minimal.
    
    df_out.to_csv(output_buffer, sep="|", index=False, na_rep="", lineterminator="\n")
    
    return output_buffer.getvalue().strip()
