package com.ccp.android

import android.content.Context

object AppGraph {
    @Volatile private var node: CcpNode? = null

    fun node(context: Context): CcpNode {
        return node ?: synchronized(this) {
            node ?: CcpNode(context.applicationContext).also { node = it }
        }
    }
}

