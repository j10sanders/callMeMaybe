"""empty message

Revision ID: 25ec89657355
Revises: 7860e66c7618
Create Date: 2018-02-14 22:17:11.294074

"""

# revision identifiers, used by Alembic.
revision = '25ec89657355'
down_revision = '7860e66c7618'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('expert', sa.Boolean(), server_default=sa.text('false'), nullable=False))
    op.drop_column('users', 'admin')
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('admin', sa.BOOLEAN(), autoincrement=False, nullable=False))
    op.drop_column('users', 'expert')
    ### end Alembic commands ###
