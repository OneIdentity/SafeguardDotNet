// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet
{
    /// <summary>
    /// Represents progress information for streaming upload and download operations.
    /// </summary>
    public class TransferProgress
    {
        /// <summary>
        /// Gets or sets the number of bytes transferred so far.
        /// </summary>
        public long BytesTransferred { get; set; }

        /// <summary>
        /// Gets or sets the total number of bytes to be transferred.
        /// </summary>
        public long BytesTotal { get; set; }

        /// <summary>
        /// Gets the percentage of the transfer that has completed (0-100).
        /// Returns 0 if BytesTotal is 0.
        /// </summary>
        public int PercentComplete => BytesTotal == 0 ? 0 : (int)((double)BytesTransferred / BytesTotal * 100);
    }
}
