"""empty message

Revision ID: fc8a248e7a90
Revises: b9098267c251
Create Date: 2018-04-25 13:43:04.045574

"""

# revision identifiers, used by Alembic.
revision = 'fc8a248e7a90'
down_revision = 'b9098267c251'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('conversations', sa.Column('guest_wallet_address', sa.String(), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('conversations', 'guest_wallet_address')
    ### end Alembic commands ###
